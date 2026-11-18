/* Guided, data-only standards editor. All API content is rendered as text. */
(() => {
  'use strict';
  const root = document.getElementById('standards_workspace');
  if (!root) return;
  const state = { catalog: null, user: null, policy: null, source: null, fields: new Map(), dirty: false };
  let sequence = 0;
  const clone = value => JSON.parse(JSON.stringify(value));
  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs)) {
      if (name.startsWith('on')) node.addEventListener(name.slice(2).toLowerCase(), value);
      else if (name === 'class') node.className = value;
      else if (name === 'text') node.textContent = value;
      else if (name in node && !name.startsWith('aria')) node[name] = value;
      else node.setAttribute(name, value);
    }
    node.append(...children.filter(Boolean).map(c => typeof c === 'string' ? document.createTextNode(c) : c));
    return node;
  };
  const button = (text, onClick, primary = false) => el('button', { type: 'button', class: 'standards-button' + (primary ? ' primary' : ''), text, onClick });
  const help = text => el('p', { class: 'standards-help', text });
  const input = (value, change, type = 'text') => el('input', { type, ...(type === 'number' ? {step:'any'} : {}), value: value ?? '', onInput: e => { change(e.target.value); state.dirty = true; } });
  const field = (label, control, note) => {
    const id = control.id || `standard_control_${++sequence}`; control.id = id;
    return el('div', { class: 'standards-field' }, el('label', { htmlFor: id, text: label }), control, note ? el('small', { text: note }) : null);
  };
  const select = (options, value, change) => {
    const control = el('select', { onChange: e => { change(e.target.value); state.dirty = true; } });
    for (const option of options) control.append(el('option', { value: option[0], text: option[1] }));
    control.value = value; return control;
  };
  const listInput = (values, change) => input((values || []).join(', '), value => change(value.split(',').map(v => v.trim()).filter(Boolean)));
  const checkbox = (checked, change) => el('input', { type: 'checkbox', checked, onChange: e => { change(e.target.checked); state.dirty = true; } });
  const notice = document.getElementById('standards_notice');
  function message(text, error = false) { notice.textContent = text; notice.className = 'standards-notice' + (error ? ' error' : ''); notice.hidden = !text; }
  async function api(path, options) {
    const response = await fetch('/api/standards' + path, options && { ...options, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(options.body) });
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || data.detail || 'The request could not be completed');
    return data;
  }
  async function action(fn) { try { message(''); await fn(); } catch (error) { message(error.message, true); } }
  async function busy(control, fn) { control.disabled = true; try { await action(fn); } finally { control.disabled = false; } }
  const baseField = () => ({ kind: 'field', source: 'device_config', path: ['name'] });
  const compare = () => ({ kind: 'compare', op: 'matches', left: baseField(), right: { kind: 'literal', value: '^NYC-SW-[0-9]{3}$' } });
  const defaultRequirement = kind => {
    if (kind === 'all' || kind === 'any') return { kind, children: [compare()] };
    if (kind === 'not') return { kind, child: compare() };
    if (kind === 'collection') return { kind, value: { kind: 'field', source: 'device_config', path: ['tags'] }, quantifier: 'every', requirement: { kind: 'compare', op: 'exists', left: { kind: 'field', source: '$item', path: [] } } };
    if (kind === 'unique') return { kind, value: baseField(), selector: { kind: 'device' }, scope: 'organization' };
    if (kind === 'related') return { kind, scope: 'site', selector: { kind: 'device', device_types: ['switch'] }, quantifier: 'one', left: { kind: 'field', source: 'device_stats', path: ['lldp_stat', 'system_name'] }, right: baseField(), requirement: { kind: 'compare', op: 'exists', left: baseField() } };
    return compare();
  };
  function pathKeys(path, change) {
    const holder = el('div');
    const draw = () => {
      holder.replaceChildren();
      path.forEach((key, index) => holder.append(el('div', { class: 'standards-toolbar' },
        input(String(key), v => { path[index] = /^\[\d+\]$/.test(v) ? Number(v.slice(1,-1)) : v; change(path); }),
        button('Remove key', () => { path.splice(index, 1); change(path); draw(); }))));
      holder.append(button('Add nested key', () => { path.push(''); change(path); draw(); }));
    };
    draw(); return holder;
  }
  async function getFields(source) {
    if (!state.fields.has(source)) state.fields.set(source, (await api('/fields?source_id=' + encodeURIComponent(source))).fields);
    return state.fields.get(source);
  }
  function operandEditor(node, changed, depth = 0) {
    const holder = el('div', { class: 'standards-operand' });
    const redraw = () => {
      holder.replaceChildren();
      const kind = node.kind || 'literal';
      holder.append(field('Value from', select([['field','Mist field'],['literal','Fixed value'],['count','Collection count'],['capture','Regex capture']], kind, value => {
        Object.keys(node).forEach(k => delete node[k]);
        Object.assign(node, value === 'field' ? baseField() : value === 'literal' ? {kind:'literal',value:''} : value === 'count' ? {kind:'count',value:baseField()} : {kind:'capture',value:baseField(),pattern:'^(?P<location>.+)$',group:'location'});
        changed(); redraw();
      })));
      if (kind === 'literal') {
        let type = node.value === null ? 'null' : Array.isArray(node.value) ? (node.value.length && node.value.every(v=>typeof v==='number')?'list_number':'list') : typeof node.value;
        const valueHolder = el('div');
        const drawValue = () => {
          valueHolder.replaceChildren();
          if (type === 'null') return;
          if (type === 'boolean') valueHolder.append(field('Value', select([['true','True'],['false','False']], String(node.value), value => { node.value = value === 'true'; changed(); })));
          else valueHolder.append(field(type.startsWith('list') ? 'Allowed values (one per line)' : 'Value', type.startsWith('list') ? el('textarea', {value:node.value.join('\n'), onInput:e=>{node.value=e.target.value.split('\n').filter(v=>v.trim()!=='').map(v=>type==='list_number'?Number(v):v);changed();}}) : input(node.value, value => {node.value = type === 'number' ? Number(value) : value;changed();}, type === 'number' ? 'number' : 'text')));
        };
        holder.append(field('Value type', select([['string','Text'],['number','Number'],['boolean','True / false'],['list','List of text values'],['list_number','List of numbers'],['null','Null']], type, value => {type=value;node.value=value.startsWith('list')?[]:value==='null'?null:value==='number'?0:value==='boolean'?true:'';changed();drawValue();})), valueHolder);
        drawValue();
      } else if (kind === 'field') {
        const choices = [...state.catalog.sources.map(s=>[s.id,s.name]),['$target','Target identity'],['$item','Current collection item']];
        holder.append(field('Data source', select(choices,node.source,value=>{node.source=value;node.path=[];changed();redraw();})));
        holder.append(field('Read from', select([['current','Current target / related device'],['root','Original target']],node.on || 'current',v=>{node.on=v;changed();})));
        const chosen = el('div', {class:'standards-pill',text:node.path.length ? node.path.join(' › ') : 'Whole record'});
        holder.append(chosen);
        if (!node.source.startsWith('$')) {
          const search = input('',()=>drawOptions()); search.placeholder='Search field name or description';
          const picker = el('select', {size:4});
          const metadata = help('Loading field definitions…'); let available=[];
          const drawOptions = () => {
            const term=search.value.toLowerCase();
            picker.replaceChildren();
            for (const f of available.filter(f=>(f.path.join(' ')+' '+f.description).toLowerCase().includes(term)).slice(0,80)) picker.append(el('option',{value:JSON.stringify(f.path),text:f.path.join(' › ')+' · '+f.types.join(' / ')}));
          };
          picker.addEventListener('change',()=>{
            if (!picker.value) return;
            node.path=JSON.parse(picker.value); chosen.textContent=node.path.join(' › '); changed();
            const f=available.find(f=>JSON.stringify(f.path)===picker.value);
            metadata.textContent=[f?.description, f?.example!==undefined?'Example: '+JSON.stringify(f.example):'',state.catalog.operations.find(op=>op.id===state.catalog.sources.find(s=>s.id===node.source)?.operation)?.path].filter(Boolean).join(' · ');
          });
          holder.append(field('Search fields',search),field('Choose a field',picker),metadata);
          getFields(node.source).then(fields=>{available=fields;drawOptions();metadata.textContent=`${fields.length.toLocaleString()} documented or observed fields. Choose a field to see its details.`;}).catch(error=>{metadata.textContent=error.message;});
        }
        const details=el('details',{},el('summary',{text:'Edit individual field keys'}),help('Each key is literal, so names containing dots remain intact. Use * for every item, or [0] for an array index.'),pathKeys(node.path,path=>{node.path=path;chosen.textContent=path.join(' › ')||'Whole record';changed();}));
        holder.append(details);
      } else if (depth < 12) {
        holder.append(operandEditor(node.value,changed,depth+1));
        if (kind === 'capture') holder.append(field('Capture pattern',input(node.pattern,v=>{node.pattern=v;changed();})),field('Group name or number',input(node.group,v=>{node.group=/^\d+$/.test(v)?Number(v):v;changed();})));
        else {
          const where = el('div');
          const drawWhere=()=>{where.replaceChildren();if(node.where)where.append(ruleEditor(node.where,value=>{node.where=value;changed();}));};
          holder.append(field('Count only matching items',checkbox(Boolean(node.where),value=>{if(value)node.where={kind:'compare',op:'exists',left:{kind:'field',source:'$item',path:[]}};else delete node.where;changed();drawWhere();})),where);drawWhere();
        }
      }
    };
    redraw(); return holder;
  }
  function selectorEditor(selector, changed, allowKind = true) {
    const holder=el('div',{class:'standards-fields'});
    if(allowKind)holder.append(field('Target level',select([['device','Devices'],['site','Sites'],['organization','Organizations']],selector.kind||'device',v=>{selector.kind=v;changed();holder.replaceWith(selectorEditor(selector,changed,allowKind));})));
    for(const [key,label] of [['org_ids','Organization IDs'],['site_ids','Site IDs'],...(selector.kind==='device'?[['models','Models']]:[])]) holder.append(field(label,listInput(selector[key],v=>{selector[key]=v;changed();}),'Leave blank for all; separate multiple values with commas.'));
    const deviceTypes=el('div',{class:'standards-toolbar'});
    for(const [type,label] of [['switch','Switches'],['ap','Access points'],['gateway','Gateways / routers']])deviceTypes.append(field(label,checkbox((selector.device_types||[]).includes(type),checked=>{const types=new Set(selector.device_types||[]);checked?types.add(type):types.delete(type);selector.device_types=[...types];changed();})));
    if((selector.kind||'device')==='device')holder.append(deviceTypes);return holder;
  }
  function ruleEditor(node, change, depth = 0) {
    const holder=el('div',{class:'standards-rule'});
    const dirty=()=>{state.dirty=true;};
    const draw=()=>{
      holder.replaceChildren();
      if(depth>12){holder.append(help('This expression is too deep to edit.'));return;}
      holder.append(field('Requirement',select([['compare','Compare values'],['all','All conditions'],['any','Any condition'],['not','Not'],['collection','Collection rule'],['related','Related devices'],['unique','Unique across organization']],node.kind,kind=>{const value=defaultRequirement(kind);change(value);node=value;dirty();draw();})));
      if(node.kind==='compare'){
        holder.append(field('Comparison',select([['matches','Matches regex'],['eq','Equals'],['ne','Does not equal'],['gt','Greater than'],['gte','At least'],['lt','Less than'],['lte','At most'],['in','Is in list'],['contains','Contains'],['exists','Is present'],['absent','Is absent']],node.op,v=>{node.op=v;if(!node.right)node.right={kind:'literal',value:''};dirty();draw();})),field('Field or value to check',operandEditor(node.left,dirty)));
        if(!['exists','absent'].includes(node.op))holder.append(field(node.op==='matches'?'Expected pattern (full name)':'Compare against',operandEditor(node.right,dirty)));
      }else if(['all','any'].includes(node.kind)){
        node.children.forEach((child,index)=>holder.append(ruleEditor(child,value=>{node.children[index]=value;dirty();},depth+1),button('Remove condition',()=>{node.children.splice(index,1);dirty();draw();})));
        holder.append(button('Add condition',()=>{node.children.push(compare());dirty();draw();}));
      }else if(node.kind==='not')holder.append(ruleEditor(node.child,value=>{node.child=value;dirty();},depth+1));
      else if(node.kind==='collection'){
        holder.append(operandEditor(node.value,dirty),field('Required items',select([['every','Every item (requires at least one)'],['any','Any item'],['none','No items']],node.quantifier,v=>{node.quantifier=v;dirty();})),help('Inside this rule, choose “Current collection item” to read each item.'),ruleEditor(node.requirement,value=>{node.requirement=value;dirty();},depth+1));
      }else if(node.kind==='unique'){
        holder.append(operandEditor(node.value,dirty),help('Compare against these targets throughout the organization. Missing organization data is reported as unevaluated.'),selectorEditor(node.selector,dirty));
      }else if(node.kind==='related'){
        holder.append(field('Search for related devices in',select([['site','The same site'],['organization','The entire organization']],node.scope,v=>{node.scope=v;dirty();})),selectorEditor(node.selector,dirty),help('Match this value on the original target…'),operandEditor(node.left,dirty),help('…to this value on candidate related devices.'),operandEditor(node.right,dirty),field('Required matches',select([['one','Exactly one (multiple matches are an error)'],['every','Every match (requires at least one)'],['any','Any match'],['none','No matching device satisfies the requirement']],node.quantifier,v=>{node.quantifier=v;dirty();})),help('Requirement for each related device. Choose “Original target” when comparing back to the original device.'),ruleEditor(node.requirement,value=>{node.requirement=value;dirty();},depth+1));
      }
    };draw();return holder;
  }
  function specialistEditor(policy) {
    const holder=el('div',{class:'standards-fields'});
    const definition=state.catalog.specialists[policy.requirement.check];
    if(definition.active)holder.append(help('Active diagnostic. Previews do not run it; explicitly request active checks on Audit.'));
    if(!Object.keys(definition.fields).length)holder.append(help('This specialist uses a validated device-specific algorithm. Edit its name, severity, applicability, and enabled state here.'));
    for(const [key,type] of Object.entries(definition.fields)){
      const params=policy.requirement.parameters;
      const label=key.replaceAll('_',' ').replace(/^./,c=>c.toUpperCase());
      const part=el('div');
      const draw=()=>{
        part.replaceChildren();
        if(type.startsWith('optional_'))part.append(field(key.includes('versions')?'Use live firmware matrix':'Disable this naming pattern',checkbox(params[key]===null,v=>{params[key]=v?null:type==='optional_strings'?[]:'.*';state.dirty=true;draw();})));
        if(params[key]===null)return;
        let control;
        if(['strings','optional_strings'].includes(type))control=el('textarea',{value:params[key].join('\n'),onInput:e=>{params[key]=e.target.value.split('\n').map(v=>v.trim()).filter(Boolean);state.dirty=true;}});
        else if(type==='mapping'||type==='groups')control=el('textarea',{value:type==='groups'?params[key].map(g=>g.join(' | ')).join('\n'):Object.entries(params[key]).map(([k,v])=>k+'='+v).join('\n'),onInput:e=>{params[key]=type==='groups'?e.target.value.split('\n').filter(Boolean).map(v=>v.split('|').map(s=>s.trim())):Object.fromEntries(e.target.value.split('\n').filter(Boolean).map(v=>{const at=v.indexOf('=');return at<0?[v,'']:[v.slice(0,at),v.slice(at+1)];}));state.dirty=true;}});
        else control=input(params[key],v=>{params[key]=['integer','positive','fraction'].includes(type)?Number(v):v;},['integer','positive','fraction'].includes(type)?'number':'text');
        part.append(field(label,control,type==='mapping'?'One variable=value per line.':type==='groups'?'One required group per line. Separate alternative variable names with |.':type.includes('strings')?'One value per line.':undefined));
      };draw();holder.append(part);
    }return holder;
  }
  function scopeControls() {
    const holder=el('div',{class:'standards-fields'});
    const ids=input('',()=>{});ids.placeholder='Choose IDs from Sites or enter site identifiers';
    const org=input('',()=>{});org.placeholder='Organization identifier';
    const entire=checkbox(false,()=>{});
    holder.append(field('Sites for live preview',ids),field('Organization',org),field('Entire organization',entire));
    holder.payload=()=>({site_ids:ids.value.split(',').map(s=>s.trim()).filter(Boolean),org_id:org.value.trim(),entire_org:entire.checked});
    const picker=el('div');
    holder.append(button('Find sites',()=>action(async()=>{
      const response=await fetch('/api/sites'+(org.value?'?org_id='+encodeURIComponent(org.value):''));const data=await response.json();
      if(!response.ok||!data.ok)throw new Error(data.error||'Could not load sites');
      picker.replaceChildren();
      const sites=Array.isArray(data.sites)?data.sites:[];
      sites.forEach(site=>picker.append(field(site.name||site.id,checkbox(ids.value.split(',').map(v=>v.trim()).includes(site.id),checked=>{let selected=ids.value.split(',').map(v=>v.trim()).filter(Boolean);selected=checked?[...new Set([...selected,site.id])]:selected.filter(v=>v!==site.id);ids.value=selected.join(', ');if(!org.value&&site.org_id)org.value=site.org_id;}))));
      if(!sites.length)picker.append(help('No sites are available.'));
    })),picker);return holder;
  }
  function renderPreview(result, holder) {
    holder.replaceChildren();
    const coverage=result.evaluation_coverage||{};
    const badges=el('div',{class:'standards-status'});
    for(const [key,label] of [['pass','Passing'],['fail','Failing'],['excluded','Excluded'],['unevaluated','Unevaluated']])badges.append(el('span',{class:key,text:`${label}: ${coverage[key]||0}`}));
    holder.append(badges);
    for(const error of result.collection_errors||[])holder.append(el('p',{class:'standards-notice error',text:`${error.source}: ${error.error}`}));
    const rows=(result.checks||[]).flatMap(check=>check.evaluations||[]);
    const table=el('table',{class:'standards-table'},el('thead',{},el('tr',{},...['Target','Result','Evidence'].map(text=>el('th',{text})))));const body=el('tbody');
    rows.forEach(row=>{
      const details=el('details',{},el('summary',{text:row.message}),el('pre',{text:JSON.stringify(row.evidence,null,2)}));
      body.append(el('tr',{},el('td',{text:row.target.name||row.target.id||'Unavailable population'}),el('td',{},el('span',{class:'standards-pill',text:row.status})),el('td',{},details)));
    });
    table.append(body);holder.append(el('div',{class:'standards-scroll'},table));
    const findings=(result.checks||[]).flatMap(c=>c.findings||[]);
    if(findings.length){const details=el('details',{},el('summary',{text:'Finding explanations'}));for(const f of findings)details.append(el('p',{text:f.message}),el('pre',{text:JSON.stringify(f.details,null,2)}));holder.append(details);}
    if(!rows.length)holder.append(help('No targets matched this policy. No passing result has been inferred.'));
  }
  function editPolicy(policy) {
    state.policy=clone(policy);state.dirty=false;renderPolicyList();
    const editor=document.getElementById('policy_editor');editor.replaceChildren();const p=state.policy;
    editor.append(el('h3',{text:p.revision?`Edit standard · revision ${p.revision}`:'Create a standard'}));
    const form=el('div',{class:'standards-form'});
    form.append(el('div',{class:'standards-fields'},field('Name',input(p.name,v=>p.name=v)),field('Severity',select([['info','Information'],['warning','Warning'],['error','Error']],p.severity,v=>p.severity=v)),field('Enabled',checkbox(p.enabled,v=>p.enabled=v))),field('Description',input(p.description||'',v=>p.description=v)));
    const targets=el('section',{class:'standards-section'},el('h4',{text:'01 · Choose targets'}),selectorEditor(p.target,()=>state.dirty=true,p.requirement.kind!=='specialist'));
    form.append(targets);
    const applicability=el('div');
    const drawWhen=()=>{applicability.replaceChildren();if(p.when)applicability.append(ruleEditor(p.when,value=>{p.when=value;state.dirty=true;}));};
    form.append(el('section',{class:'standards-section'},el('h4',{text:'02 · Applicability'}),field('Apply only when these conditions match',checkbox(Boolean(p.when),value=>{if(value)p.when=compare();else delete p.when;state.dirty=true;drawWhen();})),applicability));drawWhen();
    const requirements=el('section',{class:'standards-section'},el('h4',{text:'03 · Define requirements'}));
    if(p.requirement.kind==='specialist')requirements.append(specialistEditor(p));
    else {
      const ruleHolder=el('div');const drawRule=()=>ruleHolder.replaceChildren(ruleEditor(p.requirement,value=>{p.requirement=value;state.dirty=true;}));drawRule();
      requirements.append(el('div',{class:'standards-toolbar'},button('Switch-name pattern',()=>{p.target.kind='device';p.target.device_types=['switch'];p.requirement=compare();editPolicy(p);state.dirty=true;}),button('Unique device names',()=>{p.target.kind='device';p.requirement=defaultRequirement('unique');editPolicy(p);state.dirty=true;}),button('AP → uplink switch',()=>{p.target.kind='device';p.target.device_types=['ap'];p.requirement=defaultRequirement('related');editPolicy(p);state.dirty=true;})),ruleHolder);
    }
    form.append(requirements);
    const scope=scopeControls(),preview=el('div');
    const previewBtn=button('Preview on live data',()=>busy(previewBtn,async()=>{const result=await api('/preview',{method:'POST',body:{policy:p,...scope.payload()}});renderPreview(result,preview);}));
    const validateBtn=button('Validate',()=>action(async()=>{await api('/validate',{method:'POST',body:{policy:p}});message('This standard is valid. Preview it on live data to inspect the results.');}));
    const saveBtn=button('Save standard',()=>busy(saveBtn,async()=>{const result=await api('/policies/'+encodeURIComponent(p.id),{method:'PUT',body:{policy:p,expected_revision:p.revision||0}});state.dirty=false;await load();editPolicy(result.policy);message('Standard saved. It will be used by the next audit.');}),true);saveBtn.disabled=!state.user?.can_push;
    form.append(el('section',{class:'standards-section'},el('h4',{text:'04 · Preview and save'}),scope,el('div',{class:'standards-toolbar'},validateBtn,previewBtn,saveBtn),preview));
    if(!state.user?.can_push)form.append(help('You can inspect and preview standards. Saving requires push permission.'));
    editor.append(form);
  }
  function renderPolicyList() {
    const holder=document.getElementById('policy_list');holder.replaceChildren();
    const term=document.getElementById('policy_filter').value.toLowerCase();
    state.catalog.policies.filter(p=>(p.name+' '+p.description).toLowerCase().includes(term)).forEach(p=>{
      const control=el('button',{type:'button',class:'standards-policy','aria-current':String(state.policy?.id===p.id),onClick:()=>{if(state.dirty&&!confirm('Discard unsaved edits?'))return;editPolicy(p);}},el('strong',{text:p.name}),el('small',{text:`${p.requirement.kind==='specialist'?'Specialist':'Field rule'} · ${p.enabled?'Enabled':'Disabled'} · ${p.severity}`}));holder.append(control);
    });
    document.getElementById('policy_count').textContent=`${state.catalog.policies.length} standards · catalog revision ${state.catalog.revision}`;
  }
  function sourceEditor(source) {
    state.source=clone(source);const s=state.source;const holder=document.getElementById('source_editor');holder.replaceChildren(el('h3',{text:s.revision?'Edit data source':'Register a data source'}));
    const form=el('div',{class:'standards-form'});const opHolder=el('div');
    const search=input('',()=>drawOperations());search.placeholder='Search endpoint names and paths';const opSelect=el('select',{size:6,'aria-label':'Mist read endpoints'});
    const drawOperations=()=>{opSelect.replaceChildren();const term=search.value.toLowerCase();for(const op of state.catalog.operations.filter(op=>(op.name+' '+op.path).toLowerCase().includes(term)).slice(0,200))opSelect.append(el('option',{value:op.id,text:(op.supported?'':'Unavailable · ')+op.name+' · '+op.path}));opSelect.value=s.operation;};
    const describe=()=>{
      opHolder.replaceChildren();const op=state.catalog.operations.find(op=>op.id===s.operation);if(!op)return;
      opHolder.append(help(op.path),help(op.description),op.reason?el('p',{class:'standards-notice error',text:op.reason}):null);
      for(const parameter of op.parameters||[]){
        if(parameter.in==='path'&&['org_id','site_id','device_id','device_mac'].includes(parameter.name))continue;
        const map=parameter.in==='path'?s.bindings:s.parameters;
        opHolder.append(field(parameter.name+(parameter.required?' (required)':''),input(map[parameter.name]??'',v=>{if(v==='')delete map[parameter.name];else map[parameter.name]=v;}),parameter.description||parameter.in+' parameter'));
      }
    };
    opSelect.addEventListener('change',()=>{s.operation=opSelect.value;s.parameters={};s.bindings={};s.pagination='none';describe();});drawOperations();describe();
    form.append(field('Source name',input(s.name,v=>s.name=v)),field('Source identifier',input(s.id,v=>s.id=v),'Use letters, numbers, underscores, or hyphens.'),field('Search read operations',search),field('Mist operation',opSelect),opHolder,
      field('Records belong to',select([['device','Devices (map each record by identity)'],['site','A site (single record or collection)'],['organization','An organization (single record or collection)']],s.scope,v=>s.scope=v)),
      field('Pagination',select([['none','Single response'],['page','Page number'],['start','Start offset'],['cursor','Cursor token']],s.pagination||'none',v=>s.pagination=v)),
      field('Device types to collect',listInput(s.device_types,v=>s.device_types=v),'ap, switch, gateway. Leave blank when the endpoint does not accept a type.'),
      field('Record location',pathKeys(s.record_path,v=>s.record_path=v),'Leave empty for the response root. For search endpoints, add the key results.'),
      field('Device identity location',pathKeys(s.identity_path,v=>s.identity_path=v)),field('Device MAC location',pathKeys(s.mac_path,v=>s.mac_path=v)),
      field('Cursor query parameter',input(s.cursor_parameter||'cursor',v=>s.cursor_parameter=v)),field('Next cursor response location',pathKeys(s.next_cursor_path||[],v=>s.next_cursor_path=v)));
    if(s.id==='device_config'){form.querySelectorAll('input,select,textarea,button').forEach(control=>control.disabled=true);form.querySelector('input').disabled=false;form.append(help('This source establishes the target population. Its mapping is fixed; add another source for filtered or alternate data.'));}
    const scope=scopeControls(),preview=el('div');const test=button('Test mapping',()=>busy(test,async()=>{const result=await api('/sources/test',{method:'POST',body:{source:s,...scope.payload()}});preview.replaceChildren(help(`${result.record_count} mapped records · ${result.fields.length} fields`),el('pre',{text:JSON.stringify(result.sample,null,2)}));message('Source mapping tested successfully.');}));test.disabled=!state.user?.can_push;
    const save=button('Save source',()=>busy(save,async()=>{const result=await api('/sources/'+encodeURIComponent(s.id),{method:'PUT',body:{source:s,expected_revision:s.revision||0}});state.fields.clear();await load();sourceEditor(result.source);message('Data source saved. Its fields are available in policy editors.');}),true);save.disabled=!state.user?.can_push;
    const discoverBtn=button('Discover live fields',()=>busy(discoverBtn,async()=>{if(!s.revision)throw new Error('Save and test this source first.');const result=await api('/fields/discover',{method:'POST',body:{source_id:s.id,...scope.payload()}});state.fields.set(s.id,result.fields);preview.replaceChildren(help(`${result.fields.length} fields are now available in policy editors.`));for(const error of result.errors)preview.append(help(error.error));}));
    form.append(el('section',{class:'standards-section'},scope,el('div',{class:'standards-toolbar'},test,discoverBtn,save),preview));holder.append(form);
  }
  function renderSources() {
    const holder=document.getElementById('source_list');holder.replaceChildren();
    state.catalog.sources.forEach(source=>holder.append(el('button',{type:'button',class:'standards-card',onClick:()=>sourceEditor(source)},el('strong',{text:source.name}),el('span',{class:'standards-pill',text:source.scope}),help(state.catalog.operations.find(op=>op.id===source.operation)?.path||source.operation))));
    document.getElementById('schema_version').textContent=`Mist schema ${state.catalog.schema_version} · live discovery adds fields observed in your environment`;
  }
  async function load() {state.catalog=await api('/catalog');renderPolicyList();renderSources();}
  root.querySelectorAll('[data-standards-tab]').forEach(control=>control.addEventListener('click',()=>{
    root.querySelectorAll('[data-standards-tab]').forEach(tab=>{const active=tab===control;tab.setAttribute('aria-selected',String(active));document.getElementById(tab.getAttribute('aria-controls')).hidden=!active;});
    if(control.dataset.standardsTab==='firmware')window.dispatchEvent(new Event('standards-firmware-open'));
  }));
  document.getElementById('policy_filter').addEventListener('input',()=>state.catalog&&renderPolicyList());
  document.getElementById('new_policy').addEventListener('click',()=>{if(state.dirty&&!confirm('Discard unsaved edits?'))return;editPolicy({id:'custom_'+crypto.randomUUID().replaceAll('-',''),revision:0,name:'Switch naming convention',description:'',severity:'warning',enabled:true,target:{kind:'device',device_types:['switch']},requirement:compare()});});
  document.getElementById('new_source').addEventListener('click',()=>sourceEditor({id:'source_'+Date.now(),name:'New data source',revision:0,operation:'listSiteDevices',scope:'device',record_path:[],identity_path:['id'],mac_path:['mac'],pagination:'page',parameters:{},bindings:{},device_types:['ap','switch','gateway']}));
  document.getElementById('restore_standards').addEventListener('click',()=>action(async()=>{
    const which=document.getElementById('restore_choice').value;
    if(!confirm('Restore this saved catalog? Current policies will be replaced.'))return;
    await api('/restore',{method:'POST',body:{backup:which,expected_revision:state.catalog?.revision}});state.dirty=false;state.policy=null;await load();editPolicy(state.catalog.policies[0]);message('Validated catalog restored.');
  }));
  window.addEventListener('beforeunload',event=>{if(state.dirty){event.preventDefault();event.returnValue='';}});
  action(async()=>{
    const response=await fetch('/me');const me=await response.json();state.user=me.user;
    await load();
    document.getElementById('new_source').disabled=!state.user?.can_push;document.getElementById('restore_standards').disabled=!state.user?.can_push;
    if(state.catalog.policies.length)editPolicy(state.catalog.policies[0]);
  });
})();
