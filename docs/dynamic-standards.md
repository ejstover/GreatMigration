# Editable network standards

Standards is the shared policy catalog for this installation. It has Policies, Data Sources, and Firmware Matrix tabs. Authenticated readers can inspect and preview passive standards; saving policies, registering/testing sources, and restoring backups require push permission. All newly authored field rules report findings without writing to Mist.

## Create a naming standard

1. Open **Standards → Policies → New standard**.
2. Name the policy and select **Switches** as its device target. Optional organization IDs, site IDs, and models narrow its targets.
3. Choose **Device configuration**, search for **name**, and select that field.
4. Choose **Matches regex** and enter `^NYC-SW-[0-9]{3}$` as a text value. Matching covers the entire value.
5. Use **Find sites** to select preview sites, or enter a site identifier. Select an organization and Entire organization to preview all its sites.
6. Validate, preview, and save. Enabled policies run in the next audit.

Disable or adjust the imported Device naming convention standard if it overlaps with your new naming rule. Policy names and severity can change without invalidating exceptions; changes to selectors, conditions, requirements, or relevant source mappings invalidate their evidence.

## Advanced rules

**All**, **Any**, and **Not** groups can nest. Comparisons accept another field as well as a fixed value. Field paths contain literal keys: a property containing a dot is distinct from two nested properties. The field picker handles this automatically; individual keys can also be edited.

Arrays and dictionaries require an explicit **every**, **any**, **none**, or **count** rule. Every requires at least one item. Inside a collection rule, select **Current collection item** to read an item's properties. Count can filter its items before comparing the resulting number. Numeric comparisons require numbers; there is no implicit string/boolean conversion.

**Related devices** matches an original-target field to a candidate field and applies a requirement to the matching devices. Choose the site or organization as the search scope. Exactly one reports an evaluation error for ambiguous relationships. Within the requirement, fields can read from the related device or the original target. The AP-to-uplink preset supplies a starting field mapping; preview and adjust it to your environment's LLDP response shape. Regex capture operands can extract named or numbered groups for comparisons between names.

**Unique across organization** checks matching targets in the entire organization, including when an audit selected only one site. Related-device evidence identifies duplicates or matched devices in other sites. The target population comes from device configuration without the older audit's device-age filtering. Unassigned inventory records are available as source data but are not independent site-audit targets.

## Results and missing information

- **Pass** means the requirement was evaluated and satisfied.
- **Fail** means it was evaluated and violated. Missing properties fail normal comparisons; use presence/absence checks to explicitly permit or require absence. Null is a present value.
- **Excluded** means applicability conditions did not match.
- **Unevaluated** means data was unavailable, types were incompatible, a relationship was ambiguous, or a processing limit was reached.

Unavailable data never becomes a passing result, including through negation. Regex evaluation is limited to 25 milliseconds per match and 65,536 input characters. Expressions have node/depth limits and an evaluation budget. Pagination errors, repeated pages, HTTP errors, and unknown identities appear in collection errors. Organization-wide rules cannot pass with incomplete dependencies. Secret examples are redacted, and keyed evidence digests keep approvals specific to the actual value even when its display is redacted or shortened.

## Data sources

The bundled catalog is extracted from the official Mist OpenAPI export, version 2604.1.1. The export URL and original SHA-256 are recorded in the artifact. Its schemas describe possible fields; **Discover live fields** supplements them with properties present in your environment. Fields can be absent for some device types or models.

To register a source, select a supported passive JSON read operation, supply required resource identifiers and query parameters, choose record scope, and map the record location, identity, and MAC. Device sources map individual records to targets; site/organization sources can provide a whole collection. Configuration and statistics remain separate sources. Test the mapping against a site before saving it.

Page-number and cursor pagination are supported. Offset pagination is accepted only when documented as an offset; a time-based `start` parameter is not an offset. A nonpaginated search response declaring more total records than it returns is rejected as incomplete. Cursor sources require a documented query parameter and an explicit next-cursor response path. Unsupported operations remain visible with an explanation. External URLs, executable expressions, credential endpoints, and active diagnostics are not general-purpose sources.

Updating the schema is an explicit development step: download the official export, run `python scripts/build_standards_catalog.py downloaded-mist-openapi.json`, inspect the generated changes, and run the standards tests. Runtime discovery does not silently replace the tested schema snapshot.

## Migration and recovery

The first catalog access imports all twelve current checks and their effective settings. The default store is `backend/data/standards.json`; tests or isolated installations can override `STANDARDS_STORE_PATH`. Specialist forms retain tested algorithms for firmware, inherited configuration, health, chassis layouts, and diagnostics. Some algorithm blocks expose applicability and severity rather than arbitrary algorithm internals.

Environment naming patterns, required-variable defaults, and image requirements initialize the import. Subsequent policy edits use the catalog. Firmware matrix data retains its existing refresh behavior and explicit onboarding-policy synchronization action.

Writes are locked and atomic, with revisions preventing one editor from overwriting another. The initial import is retained in `standards.import.json`, and the previous saved catalog is retained in `standards.backup.json`. **Catalog recovery** validates either backup before activation. Invalid current content is preserved separately during recovery. A malformed catalog stops policy activation rather than falling back to a hidden default suite.

Existing supported fixes remain permission-gated. Fixes use the specialist policy's saved settings and reject stale policy evidence. Arbitrary regexes cannot always produce a safe automatic name: proposed AP names are checked against the current policy and otherwise require manual correction. Active cable diagnostics require the existing explicit active-audit choice; previews never start them.

Custom exceptions are checked against fresh evidence, policy semantics, and relevant source mapping. General policies can depend on multiple fields, so a current approved custom deviation conservatively protects its target from built-in remediation. Existing imported approvals retain their original identity until the corresponding policy's semantics change.
