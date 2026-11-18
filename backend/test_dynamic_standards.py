"""Behavioral coverage for editable standards, collection and catalog migration."""
import copy
import importlib
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

import compliance as c
import standards_store as store
from standards_catalog import catalog, default_sources, discover
from standards_collector import Collector, validate_source
from standards_engine import (Snapshot, evaluate_policy, path_value,
                              validate_policy, pattern_match, EvaluationError)
from standards_integration import build_runner
from standards_specialists import validate_specialist


def field(source="device_config", path=None, **kwargs):
    return {"kind": "field", "source": source, "path": path if path is not None else ["name"], **kwargs}


def literal(value):
    return {"kind": "literal", "value": value}


def compare(op="matches", left=None, right=None):
    return {"kind": "compare", "op": op, "left": left or field(), "right": right or literal(r"^NYC-SW-\d{3}$")}


def policy(requirement=None):
    return {"id": "custom_naming", "revision": 1, "name": "Switch naming", "severity": "warning", "enabled": True,
            "target": {"kind": "device", "device_types": ["switch"]}, "requirement": requirement or compare()}


def snapshot(documents=None):
    documents = documents or [{"id": "d1", "name": "NYC-SW-001", "type": "switch", "mac": "001122334455"}]
    snap = Snapshot(sources={s["id"]: s for s in default_sources()}, complete_orgs={"org1"})
    snap.targets = [{"kind": "device", "id": d["id"], "name": d.get("name", ""), "type": d.get("type", "switch"),
                     "org_id": "org1", "site_id": d.get("site_id", "s1"), "model": d.get("model"), "mac": d.get("mac")} for d in documents]
    snap.records["device_config"] = [{"org_id": "org1", "site_id": d.get("site_id", "s1"), "device_id": d["id"], "value": d} for d in documents]
    return snap


def statuses(p, snap):
    return [r["status"] for r in evaluate_policy(p, snap)]


def test_regex_standard_and_full_string_matching():
    p = policy()
    validate_policy(p, default_sources(), validate_specialist)
    snap = snapshot([{"id": "a", "name": "NYC-SW-001"}, {"id": "b", "name": "bad"}, {"id": "c", "name": "prefixNYC-SW-001"}])
    assert statuses(p, snap) == ["pass", "fail", "fail"]
    assert evaluate_policy(p, snap)[1]["evidence"][0]["value"] == "bad"


def test_missing_null_and_literal_dotted_paths():
    snap = snapshot([{"id": "a", "name": None, "a.b": {"v": 3}}])
    assert path_value(snap.records["device_config"][0]["value"], ["a.b", "v"]) == 3
    assert statuses(policy(compare("eq", field(path=["name"]), literal(None))), snap) == ["pass"]
    assert statuses(policy(compare("eq", field(path=["missing"]), literal(None))), snap) == ["fail"]
    assert statuses(policy(compare("absent", field(path=["missing"]))), snap) == ["pass"]
    assert statuses(policy(compare("exists", field(path=["name"]))), snap) == ["pass"]


def test_groups_applicability_and_unknowns():
    p = policy({"kind": "all", "children": [compare(), {"kind": "not", "child": compare("eq", field(), literal("bad"))}]})
    assert statuses(p, snapshot()) == ["pass"]
    p["when"] = compare("eq", field(), literal("other"))
    assert statuses(p, snapshot()) == ["excluded"]
    snap = snapshot()
    snap.errors = [{"source": "device_config", "org_id": "org1", "site_id": "s1"}]
    assert statuses(policy(), snap) == ["unevaluated"]
    p = policy({"kind": "not", "child": compare()})
    assert statuses(p, snap) == ["unevaluated"]
    missing = policy({"kind": "not", "child": compare("eq", field(path=["missing"]), literal("anything"))})
    assert statuses(missing, snapshot()) == ["fail"]
    incomplete = snapshot()
    incomplete.errors = [{"source": "device_stats", "org_id": "org1", "site_id": "s1"}]
    group = policy({"kind": "any", "children": [compare(), compare("exists", field("device_stats", ["status"]))]})
    assert statuses(group, incomplete) == ["unevaluated"]


def test_collections_counts_dictionary_keys_and_capture_groups():
    snap = snapshot([{"id": "a", "name": "NYC-SW-001", "ports": {"ge-0/0/0": {"enabled": True}, "ge-0/0/1": {"enabled": False}}}])
    collection = {"kind": "collection", "value": field(path=["ports"]), "quantifier": "every",
                  "requirement": compare("eq", field("$item", ["enabled"]), literal(True))}
    assert statuses(policy(collection), snap) == ["fail"]
    collection["quantifier"] = "any"
    assert statuses(policy(collection), snap) == ["pass"]
    count = {"kind": "count", "value": field(path=["ports"]), "where": collection["requirement"]}
    assert statuses(policy(compare("eq", count, literal(1))), snap) == ["pass"]
    capture = {"kind": "capture", "value": field(), "pattern": r"^(?P<city>[A-Z]+)-SW-\d+$", "group": "city"}
    assert statuses(policy(compare("eq", capture, literal("NYC"))), snap) == ["pass"]
    assert statuses(policy(compare("eq", field(path=["ports", "ge-0/0/0", "enabled"]), literal(True))), snap) == ["pass"]
    empty = snapshot([{"id": "a", "ports": []}])
    collection["quantifier"] = "every"
    assert statuses(policy(collection), empty) == ["fail"]


def test_cross_site_uniqueness_and_incomplete_organization():
    snap = snapshot([{"id": "a", "name": "same", "site_id": "s1"}, {"id": "b", "name": "same", "site_id": "s2"}])
    p = policy({"kind": "unique", "value": field(), "scope": "organization", "selector": {"kind": "device"}})
    rows = evaluate_policy(p, snap, {"s1"})
    assert len(rows) == 1 and rows[0]["status"] == "fail"
    assert rows[0]["evidence"][-1]["duplicates"][0]["site_id"] == "s2"
    snap.complete_orgs.clear()
    assert statuses(p, snap) == ["unevaluated", "unevaluated"]


def test_related_field_comparison_and_ambiguous_match():
    snap = snapshot([{"id": "ap", "type": "ap", "name": "NYC", "uplink": "sw"},
                     {"id": "switch", "type": "switch", "name": "sw", "location": "NYC"}])
    p = policy({"kind": "related", "scope": "site", "quantifier": "one", "selector": {"kind": "device", "device_types": ["switch"]},
                "left": field(path=["uplink"]), "right": field(),
                "requirement": compare("eq", field(path=["location"]), field(on="root"))})
    p["target"]["device_types"] = ["ap"]
    assert statuses(p, snap) == ["pass"]
    snap.targets.append({**snap.targets[1], "id": "duplicate"})
    snap.records["device_config"].append({"org_id": "org1", "site_id": "s1", "device_id": "duplicate", "value": {"name": "sw"}})
    snap._indexes.clear()
    assert statuses(p, snap) == ["unevaluated"]


@pytest.mark.parametrize("requirement", [compare("matches", right=literal("[")), compare("gte", right=literal("two")),
    compare("eq", field(path=["ports", "*"]), literal("a")), {"kind": "all", "children": []},
    {"kind": "compare", "op": "exec", "left": field(), "right": literal("anything")}])
def test_reject_invalid_policies(requirement):
    with pytest.raises(ValueError):
        validate_policy(policy(requirement), default_sources(), validate_specialist)


def test_runtime_type_errors_and_regex_timeout_do_not_become_passes():
    assert statuses(policy(compare("gt", field(), literal(2))), snapshot()) == ["unevaluated"]
    with pytest.raises(EvaluationError, match="25 milliseconds"):
        pattern_match(r"(a|aa)+$", "a" * 200 + "!")
    p = policy(compare("matches", right=literal(r"(a|aa)+$")))
    assert statuses(p, snapshot([{"id": "a", "name": "a" * 200 + "!"}])) == ["unevaluated"]
    assert statuses(policy(), snapshot()) == ["pass"]


def test_schema_refs_live_discovery_and_redaction():
    assert len(catalog()["operations"]) > 400
    fields = discover("listSiteDevices", [{"name": "test", "future_field": {"enabled": True}, "radius_secret": "dont-expose"}])
    assert next(f for f in fields if f["path"] == ["name"])["origin"] == "schema"
    assert next(f for f in fields if f["path"] == ["future_field", "enabled"])["origin"] == "observed"
    assert next(f for f in fields if f["path"] == ["radius_secret"])["example"] == "[redacted]"
    # Search responses wrap an array in results; device rules read individual records.
    search_fields = discover("searchOrgInventory", record_path=["results"])
    assert any(f["path"] == ["model"] for f in search_fields)


def test_redacted_values_still_have_value_specific_evidence():
    p = policy(compare("eq", field(path=["radius_secret"]), literal("expected")))
    first = evaluate_policy(p, snapshot([{"id": "a", "radius_secret": "first"}]))[0]
    second = evaluate_policy(p, snapshot([{"id": "a", "radius_secret": "second"}]))[0]
    assert first["evidence"][0]["value"] == second["evidence"][0]["value"] == "[redacted]"
    assert first["evidence"][0]["value_digest"] != second["evidence"][0]["value_digest"]


def test_numeric_schema_validation_rejects_name_comparison():
    with pytest.raises(ValueError, match="numeric field"):
        validate_policy(policy(compare("gt", field(), literal(3))), default_sources(), validate_specialist)


def test_rate_limit_retry_and_safe_destination(monkeypatch):
    from types import SimpleNamespace
    responses = iter([SimpleNamespace(status_code=429, headers={"Retry-After": "0"}),
                      SimpleNamespace(status_code=200, headers={}, json=lambda: [])])
    calls = []
    def get(url, **kwargs):
        calls.append((url, kwargs))
        return next(responses)
    monkeypatch.setattr('standards_collector.requests.get', get)
    collector = Collector('https://api.ac2.mist.com', {})
    assert collector.http_get('/sites/s1/devices') == []
    assert len(calls) == 2 and not calls[0][1]['allow_redirects']
    with pytest.raises(ValueError):
        Collector('https://evil.invalid', {})


def test_cursor_pagination_and_time_start_is_not_an_offset():
    source = {"id": "clients", "name": "Clients", "operation": "searchSiteWiredClients", "scope": "site",
              "record_path": ["results"], "pagination": "cursor", "cursor_parameter": "search_after", "next_cursor_path": ["next"]}
    validate_source(source)
    calls = []
    def get(path):
        calls.append(path)
        return {"results": [{"id": "one"}], "next": "next-token"} if len(calls) == 1 else {"results": [{"id": "two"}]}
    assert len(Collector('https://api.ac2.mist.com', {}, get=get).fetch(source, {"site_id": "s1"})) == 2
    assert 'search_after=next-token' in calls[-1]
    source['pagination'] = 'start'
    with pytest.raises(ValueError, match='time boundary'):
        validate_source(source)


def test_source_pagination_cache_and_identity_mapping():
    source = next(s for s in default_sources() if s["id"] == "device_config")
    source["device_types"] = ["switch"]
    calls = []
    def get(path):
        calls.append(path)
        page = int(parse_qs(urlsplit(path).query).get("page", [1])[0])
        return [{"id": f"d{i}", "name": f"SW{i}", "type": "switch"} for i in range(1000)] if page == 1 else [{"id": "last", "name": "last", "type": "switch"}]
    collector = Collector("https://api.ac2.mist.com", {}, get=get)
    contexts = [c.SiteContext("s1", "Site", site={"org_id": "org1"})]
    snap = collector.collect([source], contexts)
    assert len(snap.targets) == 1003  # org + site + 1001 devices
    assert len(calls) == 2
    collector.collect([source], contexts)
    assert len(calls) == 2
    assert snap.resolve("device_config", snap.targets[-1])["id"] == "last"


def test_repeated_pages_and_mapping_errors_are_incomplete():
    source = next(s for s in default_sources() if s["id"] == "device_config")
    source["device_types"] = ["switch"]
    repeated = [{"id": str(i), "type": "switch"} for i in range(1000)]
    collector = Collector("https://api.ac2.mist.com", {}, get=lambda path: repeated)
    snap = collector.collect([source], [c.SiteContext("s1", "Site", site={"org_id": "org1"})])
    assert "repeated a page" in snap.errors[0]["error"]
    assert not any(t["kind"] == "device" for t in snap.targets)
    collector = Collector("https://api.ac2.mist.com", {}, get=lambda path: [{"name": "no identity"}])
    snap = collector.collect([source], [c.SiteContext("s1", "Site", site={"org_id": "org1"})])
    assert snap.errors


def test_full_org_dependencies_include_other_sites():
    source = next(s for s in default_sources() if s["id"] == "device_config")
    source["device_types"] = ["switch"]
    calls = []
    def get(path):
        calls.append(path)
        if path.startswith('/orgs/'):
            return [{"id": "s1"}, {"id": "s2"}]
        return [{"id": path.split('/')[2] + '-device', "name": "same", "type": "switch"}]
    collector = Collector("https://api.ac2.mist.com", {}, get=get)
    snap = collector.collect([source], [c.SiteContext("s1", "One", site={"org_id": "org1"})], full_organization=True)
    assert snap.complete_orgs == {"org1"}
    assert {t['site_id'] for t in snap.targets if t['kind'] == 'device'} == {'s1', 's2'}


def test_unsupported_sources_and_parameters_rejected():
    source = copy.deepcopy(default_sources()[0])
    source["operation"] = "not-real"
    with pytest.raises(ValueError):
        validate_source(source)
    source = copy.deepcopy(default_sources()[0]); source["parameters"] = {"redirect": "https://evil.invalid"}
    with pytest.raises(ValueError):
        validate_source(source)


def test_migration_revisions_backup_and_recovery(monkeypatch):
    document = store.load()
    assert len(document['policies']) == len(c.DEFAULT_CHECKS)
    imported_names = {p['id']: p['name'] for p in document['policies']}
    changed = copy.deepcopy(document['policies'][0]); changed['name'] = 'Updated'
    saved = store.save_entry('policies', changed, changed['revision'])
    assert saved['revision'] == 2
    with pytest.raises(store.RevisionConflict):
        store.save_entry('policies', changed, changed['revision'])
    restored = store.restore('backup', store.load()['revision'])
    assert {p['id']: p['name'] for p in restored['policies']} == imported_names
    store.path().write_text('{broken', encoding='utf-8')
    with pytest.raises(store.StoreError):
        store.load()
    assert store.restore('import', None)['policies']
    assert store.path().with_suffix('.invalid.json').exists()


def test_failed_atomic_save_preserves_active_catalog(monkeypatch):
    document = store.load(); before = store.path().read_bytes()
    def deny(*args):
        raise OSError('simulated failure')
    monkeypatch.setattr(store.os, 'replace', deny)
    with pytest.raises(OSError):
        store.save_entry('policies', {**document['policies'][0], 'name': 'Changed'}, 1)
    assert store.path().read_bytes() == before


@pytest.mark.parametrize('check_id', [check.id for check in c.DEFAULT_CHECKS if not isinstance(check, c.SwitchCableTestCheck)])
def test_migrated_specialists_preserve_findings_and_actions(check_id):
    context = c.SiteContext('site1', 'Example', site={'org_id': 'org1'}, devices=[
        {'id': 'sw', 'type': 'switch', 'name': 'bad', 'model': 'FIXTURE', 'version': 'old', 'disable_auto_config': True,
         'psu': [{'status': 'failed'}], 'role': 'access'},
        {'id': 'ap', 'type': 'ap', 'name': 'bad-ap', 'version': 'old'}])
    old = next(check for check in c.DEFAULT_CHECKS if check.id == check_id)
    old = c.FirmwareManagementCheck(refresh_standards=False) if check_id == 'firmware_management' else type(old)()
    before = c.SiteAuditRunner([old]).run([context])
    after = build_runner([check_id], refresh_standards=False).run([context])
    for finding in after['checks'][0]['findings']:
        for action in finding.get('actions', []):
            action.get('metadata', {}).pop('standard_policy_id', None)
            action.get('metadata', {}).pop('standard_policy_hash', None)
    assert before['checks'][0]['findings'] == after['checks'][0]['findings']
    assert before['checks'][0]['actions'] == after['checks'][0]['actions']


def test_catalog_controls_execution_and_environment_is_import_only(monkeypatch):
    document = store.load()
    naming = next(p for p in document['policies'] if p['id'] == 'device_naming_convention')
    naming['requirement']['parameters']['switch_pattern'] = r'^CUSTOM-\d+$'
    store.save_entry('policies', naming, 1)
    monkeypatch.setattr(c, 'ENV_SWITCH_NAME_PATTERN', re.compile('different'))
    ctx = c.SiteContext('s1','Site',site={'org_id':'org1'},devices=[{'id':'d1','type':'switch','name':'CUSTOM-1'}])
    assert not build_runner(['device_naming_convention'], refresh_standards=False).run([ctx])['checks'][0]['findings']
    naming = next(p for p in store.load()['policies'] if p['id']=='device_naming_convention')
    naming['enabled'] = False
    store.save_entry('policies', naming, 2)
    assert build_runner(['device_naming_convention'],refresh_standards=False).checks == []


@pytest.fixture
def web(monkeypatch, tmp_path):
    app = importlib.import_module('app')
    monkeypatch.setattr(app, 'current_user', lambda request: {'name':'operator','can_push':True})
    client = TestClient(app.app, base_url='https://testserver')
    html = client.get('/login').text
    client.headers['X-CSRF-Token'] = re.search(r'name="csrf_token" value="([^"]+)"',html).group(1)
    return app, client


def test_policy_endpoints_permissions_conflicts_and_validation(web, monkeypatch):
    app, client = web
    response = client.get('/api/standards/catalog')
    assert response.status_code == 200, response.text
    p = policy(); p['revision']=0
    url='/api/standards/policies/'+p['id']
    saved=client.put(url,json={'policy':p,'expected_revision':0})
    assert saved.status_code == 200, saved.text
    assert client.put(url,json={'policy':p,'expected_revision':0}).status_code == 409
    assert client.post('/api/standards/validate',json={'policy':p}).json()['ok']
    p['requirement']['right']['value']='['
    assert client.post('/api/standards/validate',json={'policy':p}).status_code == 400
    monkeypatch.setattr(app,'current_user',lambda request:{'name':'reader','can_push':False})
    assert client.get('/api/standards/catalog').status_code == 200
    assert client.put(url,json={'policy':p,'expected_revision':1}).status_code == 403
    assert client.post('/api/standards/sources/test',json={}).status_code == 403


def test_register_test_and_discover_new_source_through_api(web, monkeypatch):
    app, client = web
    source = {"id":"future_inventory","name":"Extended inventory","operation":"searchOrgInventory","scope":"device",
              "record_path":["results"],"identity_path":["id"],"mac_path":["mac"],"pagination":"none","parameters":{},"bindings":{}}
    def get(self, path):
        if path == '/sites/site1': return {'id':'site1','name':'Site','org_id':'org1'}
        if path.startswith('/sites/site1/devices'):
            dtype=parse_qs(urlsplit(path).query).get('type',['ap'])[0]
            return [{'id':'sw','type':'switch','name':'NYC-SW-001'}] if dtype=='switch' else []
        if path == '/orgs/org1/inventory/search':
            return {'results':[{'id':'sw','future_metric': {'score':99}}], 'total':1}
        raise AssertionError(path)
    monkeypatch.setattr(Collector,'http_get',get)
    monkeypatch.setattr(app,'_load_mist_token',lambda:'test')
    tested=client.post('/api/standards/sources/test',json={'source':source,'site_ids':['site1']})
    assert tested.status_code == 200, tested.text
    assert tested.json()['record_count'] == 1
    saved=client.put('/api/standards/sources/future_inventory',json={'source':source,'expected_revision':0})
    assert saved.status_code == 200, saved.text
    found=client.post('/api/standards/fields/discover',json={'source_id':source['id'],'site_ids':['site1']})
    assert found.status_code == 200, found.text
    assert any(f['path']==['future_metric','score'] and f['example']==99 for f in found.json()['fields'])
    p=policy(compare('gte',field(source['id'],['future_metric','score']),literal(90)))
    preview=client.post('/api/standards/preview',json={'policy':p,'site_ids':['site1']})
    assert preview.status_code == 200, preview.text
    assert preview.json()['evaluation_coverage']['pass'] == 1


def test_passive_preview_and_custom_exception_semantics(web, monkeypatch):
    app, client=web
    def get(self,path):
        if path.startswith('/sites/site1/devices'):
            dtype=parse_qs(urlsplit(path).query).get('type',['ap'])[0]
            return [{'id':'sw','type':'switch','name':'bad'}] if dtype=='switch' else []
        if path=='/sites/site1':return {'id':'site1','name':'Site','org_id':'org1'}
        raise AssertionError(path)
    monkeypatch.setattr(Collector,'http_get',get)
    monkeypatch.setattr(app,'_load_mist_token',lambda:'test')
    p=policy();p['revision']=0
    result=client.post('/api/standards/preview',json={'policy':p,'site_ids':['site1']})
    assert result.status_code==200,result.text
    assert result.json()['evaluation_coverage']['fail']==1
    check=result.json()['checks'][0]
    candidate=check['findings'][0]['exception_candidate']
    saved=client.put('/api/standards/policies/custom_naming',json={'policy':p,'expected_revision':0})
    assert saved.status_code==200,saved.text
    from audit_exceptions import approve
    records_path=store.path().parent/'exceptions.json'
    record=approve(candidate,'Allowed','operator',path=records_path)
    ctx=c.SiteContext('site1','Site',site={'org_id':'org1'},mist_base_url='https://api.ac2.mist.com/api/v1')
    runner=build_runner(['custom_naming'],refresh_standards=False)
    before=runner.run([ctx],exception_records=[record],origin=ctx.mist_base_url)
    assert before['total_exceptions']==1 and before['total_findings']==0
    p=saved.json()['policy'];p['requirement']['right']['value']='^OTHER$'
    store.save_entry('policies',p,1)
    after=build_runner(['custom_naming'],refresh_standards=False).run([ctx],exception_records=[record],origin=ctx.mist_base_url)
    assert after['total_exceptions']==0 and after['total_findings']==1


def test_active_specialist_preview_never_runs_diagnostics(web,monkeypatch):
    app,client=web
    ctx=c.SiteContext('s1','Site',site={'org_id':'org1'})
    monkeypatch.setattr(app,'_gather_site_contexts',lambda *args:([ctx],[]))
    monkeypatch.setattr(app,'_load_mist_token',lambda:'test')
    def deny(*args):raise AssertionError('Active check ran during a preview')
    monkeypatch.setattr(c.SwitchCableTestCheck,'run',deny)
    p=next(p for p in store.load()['policies'] if p['id']=='switch_cable_test')
    result=client.post('/api/standards/preview',json={'policy':p,'site_ids':['s1']})
    assert result.status_code==200,result.text
    assert result.json()['evaluation_coverage']['unevaluated']==1
