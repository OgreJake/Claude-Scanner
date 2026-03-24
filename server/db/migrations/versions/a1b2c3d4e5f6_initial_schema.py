"""Initial schema — all tables for Claude Scanner Phase 1.

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2026-03-24
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = None
branch_labels = None
depends_on = None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enum(name: str) -> postgresql.ENUM:
    """Return a reference to an existing PostgreSQL enum type.

    Using postgresql.ENUM(name=..., create_type=False) is the only reliable
    way to reference a pre-created enum inside op.create_table() in
    SQLAlchemy 2.x.  sa.Enum(..., create_type=False) still emits
    CREATE TYPE in some code paths, causing DuplicateObjectError.
    """
    return postgresql.ENUM(name=name, create_type=False)


def _create_enum(name: str, values: list) -> None:
    """Create a PostgreSQL enum type idempotently via a DO block.

    postgresql.ENUM.create(checkfirst=True) does not work with asyncpg
    because the dialect introspection query cannot run inside run_sync.
    The DO block traps duplicate_object at the SQL level instead.
    """
    vals = ', '.join(f"'{v}'" for v in values)
    op.execute(sa.text(
        f"DO $$ BEGIN CREATE TYPE {name} AS ENUM ({vals});"
        f" EXCEPTION WHEN duplicate_object THEN null; END $$;"
    ))


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------

def upgrade() -> None:
    # ------------------------------------------------------------------
    # Enum types  (idempotent — safe to re-run)
    # ------------------------------------------------------------------
    _create_enum('ostype',           ['linux', 'windows', 'darwin', 'unix', 'unknown'])
    _create_enum('devicestatus',     ['online', 'offline', 'unknown'])
    _create_enum('scantype',         ['full', 'network', 'packages', 'config', 'quick'])
    _create_enum('scanstatus',       ['pending', 'running', 'completed', 'failed', 'cancelled'])
    _create_enum('severity',         ['critical', 'high', 'medium', 'low', 'none', 'unknown'])
    _create_enum('findingstatus',    ['open', 'acknowledged', 'false_positive', 'resolved'])
    _create_enum('findingtype',      ['package', 'network', 'config'])
    _create_enum('vulnsource',       ['nvd', 'osv', 'both'])
    _create_enum('complianceresult', ['pass', 'fail', 'error', 'not_applicable'])
    _create_enum('checktype',        ['command', 'file_exists', 'file_content', 'registry', 'service'])
    _create_enum('discoverymethod',  ['manual', 'ping_sweep', 'nmap', 'arp', 'import_csv'])

    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('username', sa.String(64), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('is_admin', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # ------------------------------------------------------------------
    # devices
    # ------------------------------------------------------------------
    op.create_table(
        'devices',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('hostname', sa.String(255), nullable=False),
        sa.Column('ip_address', postgresql.INET(), nullable=False),
        sa.Column('os_type',          _enum('ostype'),          nullable=False),
        sa.Column('os_name', sa.String(255), nullable=True),
        sa.Column('os_version', sa.String(128), nullable=True),
        sa.Column('os_build', sa.String(128), nullable=True),
        sa.Column('architecture', sa.String(32), nullable=True),
        sa.Column('kernel_version', sa.String(128), nullable=True),
        sa.Column('ssh_port', sa.Integer(), nullable=False, server_default='22'),
        sa.Column('winrm_port', sa.Integer(), nullable=False, server_default='5985'),
        sa.Column('winrm_use_ssl', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('credential_ref', sa.String(512), nullable=True),
        sa.Column('agent_installed', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('agent_version', sa.String(32), nullable=True),
        sa.Column('agent_last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('agent_endpoint', sa.String(512), nullable=True),
        sa.Column('tags', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('discovery_method', _enum('discoverymethod'), nullable=True),
        sa.Column('status',           _enum('devicestatus'),    nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('hostname', 'ip_address', name='uq_device_hostname_ip'),
    )
    op.create_index('ix_devices_hostname', 'devices', ['hostname'])
    op.create_index('ix_devices_ip_address', 'devices', ['ip_address'])
    op.create_index('ix_device_os_type', 'devices', ['os_type'])
    op.create_index('ix_device_status', 'devices', ['status'])

    # ------------------------------------------------------------------
    # vulnerabilities
    # ------------------------------------------------------------------
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('source',   _enum('vulnsource'), nullable=False),
        sa.Column('title', sa.String(512), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', _enum('severity'),   nullable=False),
        sa.Column('cvss_v3_score', sa.Float(), nullable=True),
        sa.Column('cvss_v3_vector', sa.String(128), nullable=True),
        sa.Column('cvss_v3_source', sa.String(128), nullable=True),
        sa.Column('cvss_v2_score', sa.Float(), nullable=True),
        sa.Column('cvss_v2_vector', sa.String(128), nullable=True),
        sa.Column('cwe_ids',           postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('affected_cpes',     postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('affected_packages', postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('references',        postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('modified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_fetched_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index('ix_vuln_severity', 'vulnerabilities', ['severity'])
    op.create_index('ix_vuln_last_fetched', 'vulnerabilities', ['last_fetched_at'])

    # ------------------------------------------------------------------
    # epss_scores
    # ------------------------------------------------------------------
    op.create_table(
        'epss_scores',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('cve_id', sa.String(64),
                  sa.ForeignKey('vulnerabilities.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('epss_score',    sa.Float(), nullable=False),
        sa.Column('percentile',    sa.Float(), nullable=False),
        sa.Column('model_version', sa.String(32), nullable=True),
        sa.Column('scored_at',  sa.DateTime(timezone=True), nullable=False),
        sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index('ix_epss_cve_id', 'epss_scores', ['cve_id'], unique=True)

    # ------------------------------------------------------------------
    # scan_jobs
    # ------------------------------------------------------------------
    op.create_table(
        'scan_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('scan_type', _enum('scantype'),   nullable=False),
        sa.Column('status',    _enum('scanstatus'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('users.id'), nullable=False),
        sa.Column('config', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('celery_task_id', sa.String(255), nullable=True),
        sa.Column('total_devices',     sa.Integer(), nullable=False, server_default='0'),
        sa.Column('completed_devices', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_devices',    sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('started_at',   sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_scan_job_status',     'scan_jobs', ['status'])
    op.create_index('ix_scan_job_created_at', 'scan_jobs', ['created_at'])

    # ------------------------------------------------------------------
    # scan_targets
    # ------------------------------------------------------------------
    op.create_table(
        'scan_targets',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('scan_job_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('scan_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('status', _enum('scanstatus'), nullable=False),
        sa.Column('celery_task_id', sa.String(255), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at',   sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_scan_targets_scan_job_id', 'scan_targets', ['scan_job_id'])
    op.create_index('ix_scan_targets_device_id',   'scan_targets', ['device_id'])

    # ------------------------------------------------------------------
    # packages
    # ------------------------------------------------------------------
    op.create_table(
        'packages',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('device_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('scan_target_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('name',            sa.String(512), nullable=False),
        sa.Column('version',         sa.String(255), nullable=False),
        sa.Column('arch',            sa.String(32),  nullable=True),
        sa.Column('package_manager', sa.String(64),  nullable=True),
        sa.Column('vendor',          sa.String(255), nullable=True),
        sa.Column('cpe',             sa.String(512), nullable=True),
        sa.Column('install_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scanned_at',   sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index('ix_packages_device_id', 'packages', ['device_id'])
    op.create_index('ix_packages_name',      'packages', ['name'])
    op.create_index('ix_packages_cpe',       'packages', ['cpe'])
    op.create_index('ix_package_device_name_version', 'packages',
                    ['device_id', 'name', 'version'])

    # ------------------------------------------------------------------
    # network_services
    # ------------------------------------------------------------------
    op.create_table(
        'network_services',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('device_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('scan_target_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('port',            sa.Integer(),    nullable=False),
        sa.Column('protocol',        sa.String(8),    nullable=False),
        sa.Column('state',           sa.String(16),   nullable=False),
        sa.Column('service_name',    sa.String(128),  nullable=True),
        sa.Column('service_product', sa.String(255),  nullable=True),
        sa.Column('service_version', sa.String(255),  nullable=True),
        sa.Column('service_extra',   sa.String(512),  nullable=True),
        sa.Column('banner',          sa.Text(),       nullable=True),
        sa.Column('cpe',             sa.String(512),  nullable=True),
        sa.Column('ssl_info', postgresql.JSON(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index('ix_network_services_device_id',       'network_services', ['device_id'])
    op.create_index('ix_netservice_device_port_proto',     'network_services',
                    ['device_id', 'port', 'protocol'])
    op.create_index('ix_network_services_cpe',             'network_services', ['cpe'])

    # ------------------------------------------------------------------
    # findings
    # ------------------------------------------------------------------
    op.create_table(
        'findings',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('device_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('scan_target_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('vulnerability_id', sa.String(64),
                  sa.ForeignKey('vulnerabilities.id'), nullable=False),
        sa.Column('finding_type', _enum('findingtype'),   nullable=False),
        sa.Column('status',       _enum('findingstatus'), nullable=False),
        sa.Column('severity',     _enum('severity'),      nullable=False),
        sa.Column('affected_component', sa.String(512), nullable=True),
        sa.Column('affected_version',   sa.String(255), nullable=True),
        sa.Column('fixed_version',      sa.String(255), nullable=True),
        sa.Column('epss_score',      sa.Float(), nullable=True),
        sa.Column('epss_percentile', sa.Float(), nullable=True),
        sa.Column('cvss_score',      sa.Float(), nullable=True),
        sa.Column('first_seen',   sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('last_seen',    sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.UniqueConstraint('device_id', 'vulnerability_id', 'affected_component',
                            name='uq_finding_device_vuln_component'),
    )
    op.create_index('ix_findings_device_id',        'findings', ['device_id'])
    op.create_index('ix_findings_scan_target_id',   'findings', ['scan_target_id'])
    op.create_index('ix_findings_vulnerability_id', 'findings', ['vulnerability_id'])
    op.create_index('ix_findings_status',           'findings', ['status'])
    op.create_index('ix_finding_severity_status',   'findings', ['severity', 'status'])
    op.create_index('ix_finding_epss',              'findings', ['epss_score'])

    # ------------------------------------------------------------------
    # benchmark_checks
    # ------------------------------------------------------------------
    op.create_table(
        'benchmark_checks',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('benchmark_name',    sa.String(255), nullable=False),
        sa.Column('benchmark_version', sa.String(32),  nullable=False),
        sa.Column('section',           sa.String(255), nullable=False),
        sa.Column('title',             sa.String(512), nullable=False),
        sa.Column('description',  sa.Text(), nullable=True),
        sa.Column('rationale',    sa.Text(), nullable=True),
        sa.Column('remediation',  sa.Text(), nullable=True),
        sa.Column('severity',    _enum('severity'),   nullable=False),
        sa.Column('os_type',     _enum('ostype'),     nullable=False),
        sa.Column('os_versions', postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('check_type',  _enum('checktype'),  nullable=False),
        sa.Column('check_command',   sa.Text(), nullable=True),
        sa.Column('expected_output', sa.Text(), nullable=True),
        sa.Column('expected_regex',  sa.Text(), nullable=True),
        sa.Column('level', sa.Integer(), nullable=False, server_default='1'),
    )
    op.create_index('ix_benchmark_checks_os_type', 'benchmark_checks', ['os_type'])

    # ------------------------------------------------------------------
    # compliance_results
    # ------------------------------------------------------------------
    op.create_table(
        'compliance_results',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('device_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('scan_target_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('check_id', sa.String(64),
                  sa.ForeignKey('benchmark_checks.id'), nullable=False),
        sa.Column('result', _enum('complianceresult'), nullable=False),
        sa.Column('actual_output', sa.Text(), nullable=True),
        sa.Column('notes',         sa.Text(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index('ix_compliance_results_device_id',      'compliance_results', ['device_id'])
    op.create_index('ix_compliance_results_scan_target_id', 'compliance_results', ['scan_target_id'])
    op.create_index('ix_compliance_results_check_id',       'compliance_results', ['check_id'])
    op.create_index('ix_compliance_device_check',           'compliance_results',
                    ['device_id', 'check_id'])

    # ------------------------------------------------------------------
    # discovery_jobs
    # ------------------------------------------------------------------
    op.create_table(
        'discovery_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('name',          sa.String(255), nullable=False),
        sa.Column('target_ranges', postgresql.JSON(), nullable=False),
        sa.Column('methods', postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('ports',   postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('status', _enum('scanstatus'), nullable=False),
        sa.Column('celery_task_id', sa.String(255), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('users.id'), nullable=False),
        sa.Column('devices_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('completed_at',  sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('discovery_jobs')
    op.drop_table('compliance_results')
    op.drop_table('benchmark_checks')
    op.drop_table('findings')
    op.drop_table('network_services')
    op.drop_table('packages')
    op.drop_table('scan_targets')
    op.drop_table('scan_jobs')
    op.drop_table('epss_scores')
    op.drop_table('vulnerabilities')
    op.drop_table('devices')
    op.drop_table('users')

    for name in ('discoverymethod', 'checktype', 'complianceresult', 'vulnsource',
                 'findingtype', 'findingstatus', 'severity', 'scanstatus',
                 'scantype', 'devicestatus', 'ostype'):
        op.execute(sa.text(
            f"DO $$ BEGIN DROP TYPE {name};"
            f" EXCEPTION WHEN undefined_object THEN null; END $$;"
        ))
