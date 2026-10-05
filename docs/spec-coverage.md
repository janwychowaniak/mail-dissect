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
covers the supplement introduced by `[D22]`. **Cases 67–69 were added for `[D24]`**, after a
report against 0.2.0 showed that a folded header was read with its line break in it (F18);
until then no case, and no fixture, had a header written across two lines. **Case 70 was added
for `[D25]`**, from the same report: an address written inside quotes. **Case 71 was added for
`[D26]`**, after a report against 0.4.0 showed that an IPv4 address at the end of a sentence was
not returned (F20); the sentence of case 28 has a comma or a space after each of its IPv4
addresses, and an IPv6 address before its full stop. **Cases 72–73 were added for `[D27]`**, after
a measurement on the published 0.5.0 image showed that a `;` after an encoded-word in a name
was rewritten as a parameter, and that two encoded-words in a name were joined only because the
image's Python happened to join them (F21); until then no case said how a part's name is read.
**Case 74 was added in 0.7.0**: until then everything a dissection did after parsing ran on the
event loop that answers `/v1/health`, and no case asked whether health answers while a
dissection is in progress.
Any further case gets the next free number and a line saying where it came from.

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
| 20 | the same input through both channels → identical results | §4 | `test_intake::test_both_channels_give_identical_results`, `…_a_large_field_survives_the_form_channel` |
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
| 67 | a folded header gives the same result as its unfolded twin — every header, the message's, a part's and a nested message's, `CRLF` and bare `LF` | §7 | `test_folding::test_folding_does_not_change_the_result`, `…_a_saved_folded_message_equals_its_unfolded_twin`, `…_a_fold_inside_a_part_header_is_not_in_the_field`, `…_a_fold_inside_a_decomposed_value_is_not_in_the_field` |
| 68 | a folded address header is decomposed, and encoded-words either side of a fold are joined | §7 | `test_folding::test_a_folded_header_yields_its_value` (+ `…_a_word_cut_by_a_fold_is_one_candidate`, `…_a_folded_content_type_keeps_its_parameters`) |
| 69 | `headers{}` is the parsed view and the `headers` artifact the record; the structured headers are the ones §7 names | §7, §13.1 | `test_folding::test_headers_are_the_parsed_view_and_the_artifact_is_the_record`, `…_the_specification_names_the_structured_headers` |
| 70 | an address entry with no domain is read once more: `"Name <address>"` and `"address"` are decomposed, in every address header; text after the address, two addresses or no address leave the entry as it was; an entry with a domain is never touched | §7 | `test_quoted_address::test_a_saved_quoted_address`, `…_every_address_header_is_read_the_same_way`, `…_anything_less_than_one_clean_mailbox_is_left_alone`, `…_the_display_name_is_never_where_an_address_comes_from` |
| 71 | a period or a hyphen that touches an IPv4 address is punctuation unless a label character continues on its far side: an address before or after one is returned without the mark, in a header, a text body and an HTML body; four numbers inside a longer token are not; a range returns both ends or neither | §11.2 | `test_ipv4_boundary::test_a_saved_message`, `…_every_source_is_read_by_the_same_rule`, `…_a_mark_with_no_label_character_beyond_it_is_punctuation`, `…_a_label_character_rules_the_address_out`, `…_a_range_returns_both_ends_or_neither`, `…_an_occurrence_the_rule_recognises_leads_the_entry_it_joins` (+ `…_what_was_measured_and_left`) |
| 72 | a part's name is read by one rule: `filename`, else `name`; the RFC 2231 form wins wherever it stands; the plain form loses the white space between two adjacent encoded-words and nothing else; the charset form is read no further and gives way to the plain one, flagged, when its charset is not taken; white space at the ends goes, a period stays; `artifacts[].filename` and the served name are that reading after §13.3 alone | §6.4, §13.3 | `test_filename::test_a_saved_name`, `…_the_plain_form_is_read_as_unstructured_text`, `…_the_rfc2231_form_wins_wherever_it_stands`, `…_a_name_declared_with_a_charset_is_read_no_further`, `…_an_unreadable_charset_form_gives_way_to_the_plain_one_and_says_so`, `…_the_flag_describes_what_was_read`, `…_white_space_at_the_ends_goes_and_a_period_stays`, `…_the_served_name_is_the_reading_after_sanitising_and_nothing_else` |
| 73 | `extension` is the text after the last period of the name's last path component, lowercased, when that period is neither its first character nor its last: `.profile` and `archive.exe.` have none | §6.4 | `test_filename::test_the_extension_follows_the_last_period_of_the_last_component` |
| 74 | `/v1/health` answers while a dissection is in progress, at every stage after the request is read — building, scanning, a document's text, the hashes, serialisation — and while the artifact store is swept | §14.3 | `test_event_loop::test_health_answers_while_a_dissection_runs` (one row per stage, and a control that runs on the loop), `…_while_the_store_is_swept` |

## Resilience

| Requirement | SPEC.md | Test |
| --- | --- | --- |
| No mutation raises an unhandled exception or exceeds the time limit | §18 | `test_fuzz::test_mutations_do_not_topple_the_service` (fixed seeds, every run) |
| The long run, with a reported seed | §18 | `test_fuzz::test_the_long_run` (marker `fuzz`, nightly) |
| Every finding becomes a permanent test | §18 | `test_fuzz::test_saved_findings_stay_fixed` over `tests/regressions/` |
| A byte above 0x7F in any header, the message's or a part's, is dissected, never a 500 | §18 | `test_fuzz::test_a_non_ascii_byte_in_any_header_is_dissected`, mutator `non_ascii_header_bytes` (`…_the_non_ascii_mutator_reaches_header_values`) |
| A folded header line, the message's or a part's, is part of what the fuzzer sends | §18 | mutator `fold_header_lines` (`test_fuzz::test_the_fold_mutator_folds`) |
| A long line the fuzzer sends has a word boundary at every character, where a candidate may start | §18, F22 | mutator `very_long_line` (`test_fuzz::test_the_long_line_has_word_boundaries_in_it`) |
| What is read out of a header holds on the interpreter the image ships: the registry's map, the values of the saved folded messages, the verdicts on the saved quoted addresses, and the names of the saved parts | §7, §6.4, `[D24]`, `[D25]`, `[D27]` | `tests/pins.py`, run by `test_folding`, `test_quoted_address` and `test_filename`, and inside the image by the CI `container` job |
| `received[]`, `auth[]` and `encoding_fallback` do not depend on where a header was folded | §7, §5.1 | `test_folding::test_received_is_decomposed_the_same_folded_or_not`, `…_authentication_results_are_decomposed_the_same_folded_or_not`, `…_a_folded_address_header_reports_what_its_unfolded_twin_reports` |
| The extractor gets the declared type only when a request header can carry it | §14.1 | `test_tools::test_the_extractor_gets_a_type_a_header_can_carry` |
| `encoding_fallback` fires when a declaration is not taken or something is substituted, and only then — and not for what the service does not read | §5.1, §7.2, §6.4, `[D20]`, `[D27]` | `test_intake::test_an_eight_bit_header_byte_is_replaced_and_reported`, `…_flagged_only_when_reading_it_fell_back`, `…_raw_utf8_in_an_address_is_read_without_loss`, `…_non_ascii_byte_in_a_part_header_is_read_and_served`, `…_filename_is_flagged_only_when_its_declaration_fails`, `test_filename::test_the_flag_describes_what_was_read` |
| The deadline is asked between messages, before every chunk of a scan and inside the HTML scan; a message reached late is returned whole with no candidates, one overtaken keeps what was found; chunks cut before white space give exactly what one scan gives | §15, `[D10]`, F23 | `test_event_loop::test_a_message_scanned_after_the_deadline_gives_no_candidates`, `…_a_scan_stops_between_chunks_at_the_deadline`, `…_the_html_scan_stops_at_the_deadline`, `test_observables::test_a_text_scanned_in_chunks_gives_what_one_scan_gives`, `…_a_candidate_across_the_chunk_size_is_found_whole` |
| A candidate may start inside a run of characters that an earlier candidate ended in, where its grammar first admits a start: an address after a quotation mark, a hyphen or two periods but never at a period, a URL after an address or a quotation mark, or after a period inside its own run | §11.2 | `test_observables::test_a_candidate_may_start_inside_a_run_another_one_ended_in` |
| No candidate contains white space: a scan cut before every white space gives what one scan gives | §11.2 | `test_observables::test_a_text_scanned_in_chunks_gives_what_one_scan_gives` |
| A run where an address or a URL with a scheme may start at every word boundary is read in linear time: the characters of a local part, of a scheme, a colon with nothing after it that completes a URL, and real base64 in one line | §15, F22 | `test_cost::test_a_run_where_a_candidate_may_start_anywhere_is_read_in_linear_time` (one case per unit), `test_observables::test_a_base64_heavy_body_does_not_blow_up_the_scan` |
| Each reader rewritten to read a run once reads what the pattern it replaced read: the scan by anchors, the address in CSS `url(`, trimming, a `Received` field, `Authentication-Results` parameters | §11.2, §7, §9, F22 | `test_exact_rewrites` (one test per reader, each against the pattern kept as its definition) |
| A URL followed by a long tail of closers or periods is trimmed, CSS `url(` repeated is read, a `Received` field of open comments and an `Authentication-Results` run are decomposed, and one value in many places is counted, each in linear time | §15, F22 | `test_cost::test_a_long_tail_of_closers_is_trimmed_in_linear_time`, `…_long_tails_of_periods_are_trimmed_in_linear_time`, `…_css_addresses_are_read_in_linear_time`, `…_a_received_field_of_open_comments_is_read_in_linear_time`, `…_an_authentication_result_with_a_long_run_is_read_in_linear_time`, `…_one_value_in_many_places_is_counted_in_linear_time` |
| A run of more than `MAX_RUN_LENGTH` non-white-space characters is skipped whole, with `truncated`, in a header value, a text body, HTML text and a document's text; at the limit it is read; any white space ends a run; finding runs costs less than reading them | §15, `[D29]`, `[D13]` | `test_limits::test_a_run_at_the_limit_is_read_and_one_past_it_is_skipped` (one case per text the grammar reads), `…_white_space_of_any_kind_ends_a_run`, `…_finding_long_runs_costs_less_than_reading_them` |
| A write and a sweep in two threads do not race: the sweep's pass over the index, and a directory the write has made and not yet filled | §13.4 | `test_artifacts::test_a_write_during_a_sweep_does_not_break_it`, `…_a_sweep_leaves_the_directory_a_write_is_filling` |
| Determinism, including array order | §17 | `test_determinism::test_the_same_message_twice`, `…both_channels_agree` |
| A stable reordering is still caught | §17 | `test_determinism::test_golden_observables` |
| The tool contracts hold against the real images | §14 | `test_live_tools` (marker `live`, by hand) |
| A defect that is known and not fixed yet is stated as the contract states it, and the statement cannot outlive the defect | §18, `CHANGELOG.md` | `test_known_defects` — each entry a saved message, a control that passes, and an expected failure in strict mode |
