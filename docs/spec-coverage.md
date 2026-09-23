# Coverage map — requirements and acceptance cases

Every functional requirement and every acceptance case has a home in
[`SPEC.md`](SPEC.md) and a test that proves it. This table is what makes a lost requirement
visible: a row with no section is a gap in the specification, and a row with no test is a
promise nobody checks.

The `Test` column is filled in as the implementation stages land; `stage N` marks a case whose
test does not exist yet. `SPEC.md` is the authority — where this map and the specification
disagree, the specification is right and this file is stale.

**Case numbering is a shared language for reporting defects, so numbers never shift.** Cases
1–65 are the acceptance set as specified. **Case 66 was added here**, after the measurement
recorded as F13 showed that the extension registry knows none of the script formats; it
covers the supplement introduced by `[D22]`. Any further case gets the next free number and a
line saying where it came from.

## Functional requirements

| # | Requirement | SPEC.md |
| --- | --- | --- |
| 1 | Descend into nested messages, including transport-encoded ones | §6.2 |
| 2 | Decode before reading (never scan raw bytes) | §7.2 |
| 3 | Handle character encodings; fall back rather than abort | §7.2 |
| 4 | Split parts into roles by one rule | §6.3 |
| 5 | Decompose every address header in full | §7 |
| 6 | Decompose `Received` into a hop chain | §7 |
| 7 | Report declared type next to detected type | §7.1 |
| 8 | Compute md5/sha1/sha256 for the source and every attachment | §5, §13.2, §15 |
| 9 | Provide a deterministic text rendering of HTML | §9.3 |
| 10 | Decompose `Authentication-Results` into every method present | §7 |
| 11 | Return all HTML addresses in two disjoint categories | §9.1 |
| 12 | Unwrap rewritten addresses, in links and resources alike | §10 |
| 13 | Extract indicator candidates from all four sources | §11 |
| 14 | Extract addresses only where they are addresses (structural rule) | §9.2 |
| 15 | Expose artifacts, ephemerally, with a lifetime | §13 |
| 16 | Return original bytes, never a reconstruction | §13.2 |

## Acceptance cases

| # | Case | SPEC.md | Test |
| --- | --- | --- | --- |
| 1 | simple single-part `text/plain` | §6.3 | `test_mime::test_simple_single_part` |
| 2 | `multipart/alternative` with HTML and text | §6.3 | `test_mime::test_alternative_with_html_and_text` |
| 3 | nested `message/rfc822` carries the original, not the envelope | §6.2 | `test_mime::test_nested_message_is_the_original` |
| 4 | two nestings in one message, and a two-level nesting | §6.2 | `test_mime::test_two_nestings_and_a_two_level_nesting` |
| 5 | long URL broken by `quoted-printable` is recovered whole | §7.2 | `test_html::test_long_url_broken_by_quoted_printable_is_recovered_whole` |
| 6 | link rewritten by a reversible wrapper | §10 | `test_html::test_reversible_wrapper` |
| 7 | link rewritten by a wrapper outside the table — unchanged, no network call | §10 | `test_html::test_wrapper_outside_the_table_passes_through` |
| 8 | RFC 2047 headers and an 8-bit body disagreeing with its declaration | §7, §7.2 | `test_mime::test_encoded_headers_and_eight_bit_body` |
| 9 | damaged MIME → `malformed_mime` plus a partial result | §15 | `test_mime::test_damaged_mime_is_normal_input` |
| 10 | oversized attachment → `truncated`, rest of the dissection complete | §15 | `test_mime::test_oversized_attachment` |
| 11 | `sha256` of the message and attachments matches an independent computation | §13.2 | `test_mime::test_all_three_hashes_match_an_independent_computation` |
| 12 | full dissection with no name resolution and no route out | §2 | `conftest::_no_network` + CI `isolation` job |
| 13 | optional dependencies disabled → `tools{}` says so, result complete otherwise | §14 | `test_tools::test_tools_disabled_make_no_calls` + `…a_tool_that_fails_does_not_fail…` |
| 14 | artifact past its lifetime, without a restart → `ARTIFACT_EXPIRED` (410) | §13.4 | `test_artifacts::test_expired_artifact_is_410_without_a_restart` |
| 15 | two nestings with HTML each → two `body_html` artifacts, different `message_index` | §13.1 | `test_mime::test_two_nestings_with_html_give_two_body_artifacts` |
| 16 | attachment with broken encoding → `attachment_unreadable`, hashes `null` | §15 | `test_mime::test_attachment_with_broken_encoding` |
| 17 | message over the input limit → `TOO_LARGE` (413), no parse attempted | §15, §16 | `test_intake::test_message_over_the_input_limit` |
| 18 | request for an artifact listing → 404, never an enumeration | §4 | `test_artifacts::test_no_listing_endpoint` |
| 19 | artifact after a restart → `ARTIFACT_NOT_FOUND` (404) | §13.4 | `test_artifacts::test_artifact_from_a_previous_process_life_is_404` |
| 20 | the same input through both channels → identical results | §4 | `test_intake::test_both_channels_give_identical_results` |
| 21 | `mailto:` anchor and `cid:` resource → both present, `host: null`, `cid_part` set | §9.1 | `test_html::test_mailto_anchor_and_cid_resource` |
| 22 | remote image and an anchor with the same address → both lists, one observable | §11 | `test_observables::test_an_address_in_both_lists_is_one_observable` + `test_html::…same_address…` |
| 23 | URL with `userinfo` → `host` and `userinfo` split correctly | §9.1 | `test_html::test_url_with_userinfo` |
| 24 | the same address five times → one entry, `occurrences: 5`, complete `sources[]` | §11.3 | `test_observables::test_the_same_address_five_times` |
| 25 | defanged address → `value` re-armed, `value_raw` original, `defanged: true` | §11.3 | `test_observables::test_defanged_address_is_re_armed_and_marked` |
| 26 | `raport.zip` → two candidates; `faktura.pdf` → only `filename` | §11.3 | `test_observables::test_ambiguous_filename_and_domain` |
| 27 | IDN host in uppercase → punycode and lowercase in `value`, path untouched | §11.3 | `test_observables::test_canonical_value_next_to_the_original` |
| 28 | private address `10.0.0.5` → present, not filtered | §11.3 | `test_observables::test_private_addresses_are_not_filtered` |
| 29 | a binary file sent as a message → `UNPARSABLE` (422) | §15, §16 | `test_intake::test_binary_file_is_unparsable` |
| 30 | one valid header, then garbage **instead of further headers** → 200 with `malformed_mime`; a binary body alone is not damage `[D23]` | §15 | `test_intake::test_one_header_and_garbage_is_accepted` (+ `…binary_body_is_not_damage`) |
| 31 | artifact write impossible → success, `artifact_id: null`, `artifact_store_failed` | §13.4, §8 | `test_artifacts::test_failed_artifact_write_still_dissects` |
| 32 | `README.md`/`raport.zip` ambiguous; `faktura.pdf`/`example.com` not | §11.3 | `test_observables::test_ambiguous_filename_and_domain` |
| 33 | `wersja.1.2` → no `domain` candidate | §11.2 | `test_observables::test_a_version_number_is_not_a_domain` |
| 34 | `bit.ly/xyz` and `www.example.com` → `url` plus their hosts as `domain` | §11.2 | `test_observables::test_url_yields_its_host_as_well` |
| 35 | email address in content → `email` plus its domain as `domain` | §11.2 | `test_observables::test_email_yields_its_domain_as_well` |
| 36 | `/v1/health` → 200 with dependencies off, all fields, registry versions | §14.3, §12 | `test_health::test_health_reports_registry_versions_with_tools_disabled` |
| 37 | `multipart/mixed` with two `text/plain` → first is the body | §6.3 | `test_mime::test_mixed_with_two_text_parts` |
| 38 | `multipart/related` with `alternative` inside and a `cid:` image | §6.3, §9.1 | `test_html::test_related_with_alternative_inside` |
| 39 | two attachments with identical names → distinct `part_index` | §5.2 | `test_mime::test_two_attachments_with_the_same_name` |
| 40 | wrapper inside a wrapper → unwrapped to a fixed point | §10 | `test_html::test_wrapper_inside_a_wrapper` |
| 41 | entry matches but the target cannot be extracted → `unwrap_failed: true` | §10 | `test_html::test_matching_entry_that_cannot_unwrap` |
| 42 | malformed `UNWRAPPERS` → the service does not start | §10, §19 | `test_settings::test_malformed_unwrappers_stop_the_service` |
| 43 | address decomposition across `From`, `To`, `Reply-To` | §7 | `test_mime::test_address_decomposition` |
| 44 | three-hop `Received` chain, `null` where the header was incomplete | §7 | `test_mime::test_received_chain` |
| 45 | `Authentication-Results` with four methods including a non-standard one | §7 | `test_mime::test_authentication_results_with_four_methods` |
| 46 | `headers` completeness: custom and repeated headers | §7 | `test_intake::test_headers_are_complete_and_ordered` |
| 47 | declared type ≠ detected type, with no comment from the service | §7.1 | `test_mime::test_declared_type_differs_from_detected` |
| 48 | `charset_declared` ≠ `charset_used`, `encoding_fallback`, content readable | §7.2 | `test_mime::test_declared_charset_differs_from_used` + `test_decode::test_the_ladder` |
| 49 | `text_from_html` with and without a `text/plain` part | §9.3 | `test_html::test_text_from_html` |
| 50 | inline threshold for `html` and for `text_from_html` | §8 | `test_html::test_inline_threshold_per_representation` |
| 51 | all three hashes for the message and every attachment | §13.2 | `test_mime::test_all_three_hashes_match_an_independent_computation` |
| 52 | working Tika → `attachment_text`, candidates with an `attachment` source | §14.1 | `test_tools::test_working_text_extractor` |
| 53 | working renderer → `screenshot` artifact with `message_index` | §14.2 | `test_tools::test_working_renderer` |
| 54 | whole-dissection budget exceeded → 200, `ok: true`, `truncated` | §15 | `test_tools::test_the_whole_budget_is_enforced_between_units` |
| 55 | unknown `artifact_id` with a valid `dissect_id` → 404 | §16 | `test_artifacts::test_unknown_artifact_id_with_a_valid_dissect_id` |
| 56 | candidates from headers carry `header_name` and `header_index` | §11.1 | `test_observables::test_candidates_from_headers_name_their_place` |
| 57 | artifact response headers: octet-stream, sanitised filename, nosniff | §13.3 | `test_mime::test_attachment_filename_is_sanitised_in_the_response_header` |
| 58 | mixed tool outcome → worst wins (`timeout`), per-item links still correct | §14 | `test_tools::test_the_worst_outcome_wins` |
| 59 | nested message screenshot → two `screenshot` artifacts | §13.1, §14.2 | `test_tools::test_nested_message_gets_its_own_screenshot` |
| 60 | rewritten resource → target in `href`, `rewritten_from`, `unwrap_failed` on failure | §10 | `test_html::test_rewritten_resource` |
| 61 | health and dependencies: `disabled` with no traffic, `down`, one probe per TTL | §14.3 | `test_health::test_disabled_tools_are_never_probed`, `…_unreachable_tools_are_down…` |
| 62 | stable core of `observables[]` with and without document extraction | §11.1 | `test_tools::test_the_deterministic_core_does_not_move` |
| 63 | nested original byte-for-byte, hash matching an independent computation | §13.2 | `test_mime::test_nested_original_is_byte_identical` |
| 64 | transport-encoded nesting → a parsed message, `eml` after decoding | §6.2 | `test_mime::test_transport_encoded_nesting_is_still_a_message` |
| 65 | part count far over the limit → `truncated` in scan time, no full tree | §15 | `test_mime::test_part_count_far_over_the_limit_is_cut_in_scan_time` |
| 66 | `payload.scr` in body text → no candidate with an empty supplement, a `filename` candidate with `EXTRA_FILE_EXTENSIONS=scr` | §12, §11.2 | `test_observables::test_the_extension_supplement_changes_recognition` + `test_registries::…supplement…` |

## Resilience

| Requirement | SPEC.md | Test |
| --- | --- | --- |
| No mutation raises an unhandled exception or exceeds the time limit | §18 | `test_fuzz::test_mutations_do_not_topple_the_service` (fixed seeds, every run) |
| The long run, with a reported seed | §18 | `test_fuzz::test_the_long_run` (marker `fuzz`, nightly) |
| Every finding becomes a permanent test | §18 | `test_fuzz::test_saved_findings_stay_fixed` over `tests/regressions/` |
| A byte above 0x7F in any header, the message's or a part's, is dissected, never a 500 | §18 | `test_fuzz::test_a_non_ascii_byte_in_any_header_is_dissected`, mutator `non_ascii_header_bytes` |
| The extractor gets the declared type only when a request header can carry it | §14.1 | `test_tools::test_the_extractor_gets_a_type_a_header_can_carry` |
| `encoding_fallback` fires when a declaration is not taken or something is substituted, and only then | §5.1, §7.2, `[D20]` | `test_intake::test_an_eight_bit_header_byte_is_replaced_and_reported`, `…_flagged_only_when_reading_it_fell_back`, `…_raw_utf8_in_an_address_is_read_without_loss`, `…_non_ascii_byte_in_a_part_header_is_read_and_served`, `…_filename_is_flagged_only_when_its_declaration_fails` |
| Determinism, including array order | §17 | `test_determinism::test_the_same_message_twice`, `…both_channels_agree` |
| A stable reordering is still caught | §17 | `test_determinism::test_golden_observables` |
| The tool contracts hold against the real images | §14 | `test_live_tools` (marker `live`, by hand) |
