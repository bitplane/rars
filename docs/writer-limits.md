# Writer limits

What each writer accepts, and what it holds in memory while writing. Every
cell names the test that pins it, or the issue tracking it.

Formats go by their `--format` names. `rar14` writes RAR 1.3 archives, and
`rar29`, `rar30` and `rar40` behave the same, written here as `rar40`.

## Sizes

| format | largest member | largest archive or set | tests |
|---|---|---|---|
| `rar14` | 4 GiB − 1 (32-bit size fields) | single: no limit; volumes: 901 (`.rar`, `.r00`…`.z99`), one member | `writer_limits_are_invalid_arguments`, `streaming_writer_attributes_source_size_failures`, `old_style_names_roll_from_r99_to_s00_as_rar_4_does` |
| `rar15` | 4 GiB − 1, refused before the member is opened | as `rar40` | `rar15_refuses_members_over_4_gib_before_opening_them`, `writer_limits_and_invalid_options_are_not_archive_corruption` |
| `rar20` | 2⁶⁴ − 1; high size fields from 4 GiB − 1 | single: no limit; volumes: 901 | `a_member_past_4_gib_reads_back_at_its_full_size`, `a_rar20_member_of_all_ones_bytes_gives_its_size_in_full`, `rar20_members_past_2_gib_ask_for_a_large_file_reader` |
| `rar40` | 2⁶⁴ − 1; high size fields from 2 GiB | single: no limit; volumes: 901 | `rar29_members_past_2_gib_carry_the_large_size_fields`, `a_member_over_4_gib_streams_into_a_set_but_is_refused_in_memory`, `old_style_volume_writer_rolls_past_r99`, `stored_members_over_4_gib_round_trip`* |
| `rar50`, `rar70` | 2⁶⁴ − 1; a named filter covers the first 4 GiB, as automatic filters do | no limit; a recovery record covers at most 858,993,124,400 bytes, so a larger archive is refused before writing and volumes close at that size | `rar5_members_over_4_gib_round_trip`*, `explicit_filter_runs_past_4_gib_are_coded_unfiltered`, `a_layout_whose_recovery_record_cannot_be_built_is_refused`, `a_volume_closes_before_its_recovery_record_stops_covering_it`, `compression_dictionary_fields_obey_version_and_wire_limits`, `encode_options_refuse_a_valid_dictionary_above_the_host_limit` |

\* Ignored by default, because they write archives over 4 GiB; run with
`cargo test --release -p rars --test legacy_large_members --test legacy_large_volumes -- --ignored`.

A legacy compressed member held in memory, rather than streamed, is capped at
4 GiB in a volume set ("compressed legacy volume sets cannot hold a member
over 4 GiB"). Every format refuses a volume size too small for its headers,
and no volume comes out longer than asked: `a_volume_size_too_small_for_the_headers_is_refused`,
`no_volume_is_longer_than_the_volume_size`, `legacy_volumes_fill_the_volume_size_exactly`.

## Options

Pinned by `writer_limits_table_matches_what_each_format_supports`.

| format | archive | solid | password | encrypted headers | recovery record | `--memory-limit` | `--temp-dir` |
|---|---|---|---|---|---|---|---|
| `rar14` | single | yes | yes | no | no | yes | yes |
| `rar14` | volumes | yes | no | no | no | no | no |
| `rar15` | single | yes | yes | no | no | yes | yes |
| `rar15` | volumes | yes | yes | no | no | no | no |
| `rar20` | single | yes | yes | no | no | yes | yes |
| `rar20` | volumes | yes | yes | no | no | no | no |
| `rar40` | single | yes | yes | yes | no | yes | yes |
| `rar40` | volumes | yes | yes | yes | no | no | no |
| `rar50`, `rar70` | either | yes | yes | yes | yes | yes | yes |

## Memory

Peak resident memory writing 1 GiB (512 MiB of random bytes, then 512 MiB of
text) at `--level 3`, on a 32-thread machine. Single archives ran under
`--memory-limit 256m`. Legacy volume sets refuse that flag, so they ran
without it. The solid column is two 512 MiB members.

| format | stored | compressed, to a file | compressed, to a pipe | solid | password | encrypted headers | volumes, stored / compressed | recovery |
|---|---|---|---|---|---|---|---|---|
| `rar14` | 7 MB | 10 MB | 10 MB | 10 MB | 10 MB | refused | 3.2 GB / 2.3 GB | refused |
| `rar15` | 6 MB | 10 MB | 10 MB | 10 MB | 11 MB | refused | 6 MB / 10 MB | refused |
| `rar20` | 6 MB | 27 MB | 28 MB | 25 MB | 31 MB | refused | 6 MB / 28 MB | refused |
| `rar40` | 6 MB | 144 MB | 145 MB | 181 MB | 146 MB | 145 MB | 6 MB / 193 MB | refused |
| `rar50` | 6 MB | 219 MB | 221 MB | 222 MB | 214 MB | 222 MB | 221 MB | 220 MB |
| `rar70` | 6 MB | 222 MB | not run | 223 MB | 221 MB | 222 MB | 219 MB | 225 MB |

What each writer holds, what bounds it, and the tests that pin it:

| format and path | holds | bounded by | tests |
|---|---|---|---|
| any format, stored | a copy buffer; the source is read twice, for the CRC and then the copy | constant | `a_stored_member_is_copied_through_not_loaded_in_every_format`, `stored_split_member_reads_its_source_at_most_twice` |
| `rar14` compressed | one 64 KiB window, the next 1 MiB and a match index over the window; a member over 64 MiB is packed into a spool in the temp directory, verified by decoding the spool against the source, then copied out | the window, plus disk | `a_spooled_member_writes_the_archive_the_in_memory_writer_does`, `a_spooled_member_is_encrypted_as_it_is_copied_out`, `a_member_coded_a_window_at_a_time_packs_as_it_does_whole` |
| `rar15` compressed | one 64 KiB window, the next 1 MiB and a match index over the window | the window, whatever the member's size | `rar15_charges_an_index_whatever_the_member_size`, `a_streamed_rar15_member_writes_the_archive_the_in_memory_writer_does`, `solid_rar15_members_stream_on_the_chain_and_are_never_stored`, `a_member_coded_a_window_at_a_time_packs_as_it_does_whole` |
| `rar20` compressed | one 1 MiB block and its tables | the block, whatever the member's size | `rar20_charges_a_block_whatever_the_member_size`, `a_streamed_rar20_member_writes_the_archive_the_in_memory_writer_does`, `solid_rar20_members_stream_on_the_chain_and_leave_it_for_the_next` |
| `rar40` compressed | the LZ window or PPMd model; levels 4 and 5 try larger models, up to 128 MB (338 MB peak for 120 MB of text at level 5, 149 MB at level 3) | dictionary and level | `a_streamed_member_is_charged_what_it_holds_not_its_size`, `a_streamed_member_writes_the_archive_the_in_memory_writer_does`, `rar29_levels_are_charged_for_the_models_and_parse_they_hold` |
| `rar15`, `rar20`, `rar40` to a pipe | as to a file; a member over 64 MiB is packed into a spool in the temp directory first | as to a file, plus disk | `a_streamed_rar15_member_writes_the_archive_the_in_memory_writer_does`, `a_piped_member_is_spooled_into_the_archive_a_file_gets`, `a_piped_password_protected_member_is_spooled_and_encrypted` |
| legacy members of 64 MiB or less | the member and its packed form, one per member in flight | `--memory-limit` decides how many are in flight; copies it doesn't count are #336 | `a_compressed_member_is_charged_itself_its_packed_form_and_a_fixed_index`, `an_oversized_member_is_admitted_alone_rather_than_refused`, `legacy_resource_limits_fail_before_opening_a_member_or_writing_output` |
| legacy stored with a password, single archive | the whole member (#334) | its size | `an_encrypted_stored_member_is_charged_for_the_member_it_holds` |
| `rar40` with a named filter | as compressed: a member over 64 MiB streams, filtered a segment at a time (79 MB for the 1 GiB above, 3.8 GB before #335); under `--ppmd` too, a record at a time (121 MB for 512 MiB of ELF binaries, 1.4 GB before #345) | dictionary and level | `a_member_with_a_named_filter_streams_what_the_in_memory_writer_writes`, `a_named_filter_streams_on_a_solid_chain_and_through_a_pipe`, `a_filtered_ppmd_member_read_in_segments_codes_to_the_in_memory_bytes` |
| `rar14` volume set | the input and every volume (#340) | nothing | |
| `rar15`, `rar20`, `rar40` volume set | as a single archive: large members stream into the set | as a single archive | `a_streamed_rar15_member_splits_into_the_volumes_the_in_memory_writer_does`, `a_streamed_rar20_member_splits_into_the_volumes_the_in_memory_writer_does`, `a_compressed_member_over_4_gib_streams_into_a_set`* |
| `rar50`, `rar70` compressed | blocks in flight; each member spooled to disk before it's written | `--memory-limit`, dictionary × jobs; disk only if a spool quota is set | `default_builder_and_explicit_dictionaries_fit_fixed_managed_ceilings`, `two_codec_workers_hold_admitted_capacity_concurrently`, `the_workspace_charge_covers_what_a_member_measured`, `spool_quota_does_not_change_successful_archive_bytes` |
| `rar50`, `rar70` solid | the dictionary carried between members | dictionary | `solid_multirun_history_fits_fixed_ceiling_and_extracts` |
| `rar50`, `rar70` recovery | the parity, or 64 MiB stripes of it under pressure | `--memory-limit` | `recovery_memory_mode_switches_to_striping_under_pressure`, `striped_recovery_matches_resident_recovery_byte_for_byte` |
| `rar50`, `rar70` encrypted | a cipher block; volume sets spool the ciphertext | constant, plus disk | `encrypted_streaming_writer_round_trips_across_input_blocks`, `encrypted_volume_preparation_uses_the_shared_spool_quota` |

Some library calls hold the whole archive by design, because they return it:
`Builder::to_bytes`, `Builder::build_volumes` and `Rar50Writer::finish`.
A RAR 5 write shares `Builder::add_bytes` payloads rather than copying them
(#337). Some copies are not counted against the budget (#336).
