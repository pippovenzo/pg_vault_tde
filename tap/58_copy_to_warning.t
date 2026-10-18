# tap/58_copy_to_warning.t — ProcessUtility hook warning on COPY TO plaintext export
#
# Roadmap v1.8 §10: COPY TO / pg_dump on an encrypted_heap table exports
# unencrypted plaintext.  The ProcessUtility hook emits an advisory WARNING
# reminding the user that data is exported in plaintext and recommending pg_dump_tde,
# controlled by GUC pg_vault_tde.dump_plaintext_warning = on (default on).
#
# Asserts:
# 1-2)   COPY t_enc TO STDOUT succeeds and emits WARNING naming t_enc
# 3-4)   COPY (SELECT * FROM t_enc) TO STDOUT succeeds and emits WARNING naming t_enc
# 5-6)   COPY t_plain TO STDOUT succeeds without warning
# 7-8)   SET pg_vault_tde.dump_plaintext_warning = off suppresses the warning
# 9-10)  COPY t_enc FROM STDIN succeeds without warning (import is safe)
# 11-12) COPY part_enc TO STDOUT on partitioned table with encrypted partition emits WARNING
use strict;
use warnings;
use Test::More tests => 12;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

END { system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*') }

system('/bin/sh', '-c', 'rm -rf /var/lib/pg_vault_tde/*');
my $node = PostgreSQL::Test::Cluster->new('copy_warn_node');
$node->init;
$node->append_conf('postgresql.conf',
    "shared_preload_libraries = 'pg_vault_tde'\n"
  . "pg_vault_tde.kms_provider = 'local'\n"
  . "pg_vault_tde.wallet_passphrase_command = 'echo test-password'\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_vault_tde;');
$node->safe_psql('postgres', "SELECT pg_vault_tde_wallet_init('test-password')");

# ── Setup tables ───────────────────────────────────────────────────────────
$node->safe_psql('postgres', q{
    CREATE TABLE t_enc (id int, val text) USING encrypted_heap;
    INSERT INTO t_enc VALUES (1, 'secret_data');

    CREATE TABLE t_plain (id int, val text) USING heap;
    INSERT INTO t_plain VALUES (1, 'public_data');

    CREATE TABLE part_enc (id int, val text) PARTITION BY RANGE (id);
    CREATE TABLE part_enc_1 PARTITION OF part_enc FOR VALUES FROM (1) TO (100) USING encrypted_heap;
    INSERT INTO part_enc VALUES (10, 'part_secret_data');
});

# ── 1. Standard COPY TO on encrypted_heap table (default GUC = on) ────────
{
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "COPY t_enc TO STDOUT;");
    is($rc, 0, '1: COPY t_enc TO STDOUT succeeds');
    like($stderr, qr/pg_vault_tde: COPY TO on encrypted_heap table "t_enc" exports plaintext/,
        '2: ... and emits WARNING naming t_enc');
}

# ── 2. Query-based COPY (SELECT ...) TO STDOUT ─────────────────────────────
{
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "COPY (SELECT * FROM t_enc) TO STDOUT;");
    is($rc, 0, '3: COPY (SELECT * FROM t_enc) TO STDOUT succeeds');
    like($stderr, qr/pg_vault_tde: COPY TO on encrypted_heap table "t_enc" exports plaintext/,
        '4: ... and emits WARNING naming t_enc for query syntax');
}

# ── 3. Plain heap table: no warning ────────────────────────────────────────
{
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "COPY t_plain TO STDOUT;");
    is($rc, 0, '5: COPY t_plain TO STDOUT succeeds');
    unlike($stderr, qr/COPY TO on encrypted_heap table/,
        '6: ... and plain heap table emits NO warning');
}

# ── 4. GUC disabled: dump_plaintext_warning = off ──────────────────────────
{
    my ($rc, $stdout, $stderr) = $node->psql('postgres', q{
        SET pg_vault_tde.dump_plaintext_warning = off;
        COPY t_enc TO STDOUT;
    });
    is($rc, 0, '7: COPY t_enc TO STDOUT with dump_plaintext_warning = off succeeds');
    unlike($stderr, qr/COPY TO on encrypted_heap table/,
        '8: ... and emits NO warning when setting is off');
}

# ── 5. COPY FROM STDIN (import): no warning ────────────────────────────────
{
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "COPY t_enc FROM STDIN;\n2\timported_secret\n\\.\n");
    is($rc, 0, '9: COPY t_enc FROM STDIN succeeds');
    unlike($stderr, qr/COPY TO on encrypted_heap table/,
        '10: ... and COPY FROM (import) emits NO warning');
}

# ── 6. Partitioned table with encrypted_heap partition ────────────────────
{
    my ($rc, $stdout, $stderr) = $node->psql('postgres',
        "COPY (SELECT * FROM part_enc) TO STDOUT;");
    is($rc, 0, '11: COPY (SELECT * FROM part_enc) TO STDOUT on partitioned table succeeds');
    like($stderr, qr/pg_vault_tde: COPY TO on encrypted_heap table "part_enc" exports plaintext/,
        '12: ... and emits WARNING for inherited encrypted_heap partition');
}

$node->stop;
