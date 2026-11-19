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
| `rar50`, `rar70` | 2⁶⁴ − 1 | no limit; a recovery record caps an archive or volume at about 859 GB, checked only while writing (#338) | `rar5_members_over_4_gib_round_trip`*, `compression_dictionary_fields_obey_version_and_wire_limits`, `encode_options_refuse_a_valid_dictionary_above_the_host_limit` |

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
| `rar14` | single | yes | yes | no | no | yes | no |
| `rar14` | volumes | yes | no | no | no | no | no |
| `rar15` | single | yes | yes | no | no | yes | no |
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
| `rar14` | 7 MB | 11.8 GB | 11.8 GB | 7.0 GB | 11.8 GB | refused | 3.2 GB / 11.9 GB | refused |
| `rar15` | 6 MB | 11.8 GB | 11.9 GB | 7.0 GB | 11.8 GB | refused | 6 MB / 11.8 GB | refused |
| `rar20` | 6 MB | 27 MB | 28 MB | 25 MB | 31 MB | refused | 6 MB / 28 MB | refused |
| `rar40` | 6 MB | 144 MB | 145 MB | 181 MB | 146 MB | 145 MB | 6 MB / 193 MB | refused |
| `rar50` | 6 MB | 219 MB | 221 MB | 222 MB | 214 MB | 222 MB | 221 MB | 220 MB |
| `rar70` | 6 MB | 222 MB | not run | 223 MB | 221 MB | 222 MB | 219 MB | 225 MB |

What each writer holds, what bounds it, and the tests that pin it:

| format and path | holds | bounded by | tests |
|---|---|---|---|
| any format, stored | a copy buffer; the source is read twice, for the CRC and then the copy | constant | `a_stored_member_is_copied_through_not_loaded_in_every_format`, `stored_split_member_reads_its_source_at_most_twice` |
| `rar14`, `rar15` compressed | the whole member, a match index of about 8–16 bytes per byte and, for `rar14`, a verifying decode | nothing: the charge admits one oversized member alone (#332) | `an_oversized_member_is_admitted_alone_rather_than_refused`, `rar15_and_rar20_parse_levels_are_charged_for_what_they_hold` (`rar15` only) |
| `rar20` compressed | one 1 MiB block and its tables | the block, whatever the member's size | `rar20_charges_a_block_whatever_the_member_size`, `a_streamed_rar20_member_writes_the_archive_the_in_memory_writer_does`, `solid_rar20_members_stream_on_the_chain_and_leave_it_for_the_next` |
| `rar40` compressed | the LZ window or PPMd model | dictionary and level | `a_streamed_member_is_charged_what_it_holds_not_its_size`, `a_streamed_member_writes_the_archive_the_in_memory_writer_does` |
| `rar20`, `rar40` to a pipe | as to a file; a member over 64 MiB is packed into a spool in the temp directory first | as to a file, plus disk | `a_piped_member_is_spooled_into_the_archive_a_file_gets`, `a_piped_password_protected_member_is_spooled_and_encrypted` |
| `rar15`, `rar20`, `rar40` members of 64 MiB or less | the member and its packed form, one per member in flight | `--memory-limit` decides how many are in flight; copies it doesn't count are #336 | `an_oversized_member_is_admitted_alone_rather_than_refused`, `legacy_resource_limits_fail_before_opening_a_member_or_writing_output` |
| legacy stored with a password, single archive | the whole member (#334) | its size | `an_encrypted_stored_member_is_charged_for_the_member_it_holds` |
| `rar40` with a named filter | as compressed: a member over 64 MiB streams, filtered a segment at a time (79 MB for the 1 GiB above, 3.8 GB before #335); under `--ppmd` the whole member, filtered and packed (#345) | dictionary and level; under `--ppmd`, nothing | `a_member_with_a_named_filter_streams_what_the_in_memory_writer_writes`, `a_named_filter_streams_on_a_solid_chain_and_through_a_pipe` |
| `rar14` volume set | the input and every volume (#340) | nothing | |
| `rar20`, `rar40` volume set | as a single archive: large members stream into the set | as a single archive | `a_streamed_rar20_member_splits_into_the_volumes_the_in_memory_writer_does`, `a_compressed_member_over_4_gib_streams_into_a_set`* |
| `rar50`, `rar70` compressed | blocks in flight; each member spooled to disk before it's written | `--memory-limit`, dictionary × jobs; disk only if a spool quota is set | `default_builder_and_explicit_dictionaries_fit_fixed_managed_ceilings`, `two_codec_workers_hold_admitted_capacity_concurrently`, `the_workspace_charge_covers_what_a_member_measured`, `spool_quota_does_not_change_successful_archive_bytes` |
| `rar50`, `rar70` solid | the dictionary carried between members | dictionary | `solid_multirun_history_fits_fixed_ceiling_and_extracts` |
| `rar50`, `rar70` recovery | the parity, or 64 MiB stripes of it under pressure | `--memory-limit` | `recovery_memory_mode_switches_to_striping_under_pressure`, `striped_recovery_matches_resident_recovery_byte_for_byte` |
| `rar50`, `rar70` encrypted | a cipher block; volume sets spool the ciphertext | constant, plus disk | `encrypted_streaming_writer_round_trips_across_input_blocks`, `encrypted_volume_preparation_uses_the_shared_spool_quota` |

Some library calls hold the whole archive by design, because they return it:
`Builder::to_bytes`, `Builder::build_volumes` and `Rar50Writer::finish`.
`Builder::add_bytes` payloads are copied again for a RAR 5 write (#337). Some
copies are not counted against the budget (#336).
