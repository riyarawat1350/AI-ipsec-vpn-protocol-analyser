"""Unit tests for database models, cascade deletions, and PostgreSQL schema compatibility (TASK-003)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateTable

from backend.app.db.base import Base, set_sqlite_pragma
from backend.app.db.models import (
    AnalysisModel,
    AnomalyWindowModel,
    EvidenceModel,
    FindingModel,
    IkeMessageModel,
    IkeSessionModel,
    IocModel,
    IpsecFlowModel,
    ReportModel,
    TimelineEventModel,
    UploadModel,
)


@pytest.fixture
def test_db():
    """In-memory SQLite database with foreign keys enabled."""
    engine = create_engine("sqlite:///:memory:")
    # Register foreign key pragma
    from sqlalchemy import event
    event.listen(engine, "connect", set_sqlite_pragma)

    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.mark.unit
def test_crud_and_cascade_delete(test_db):
    """Test full entity creation, foreign key relations, and cascade deletion on SQLite."""
    # 1. Create Upload
    upload = UploadModel(
        original_filename="sample.pcap",
        stored_path="/data/uploads/sample.pcap",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=1024,
        detected_format="pcap",
    )
    test_db.add(upload)
    test_db.commit()

    # 2. Create Analysis
    analysis = AnalysisModel(
        upload_id=upload.id,
        status="completed",
        stage="completed",
        progress=100,
        policy_id="nist_default",
        posture_score=85.0,
        grade="B",
    )
    test_db.add(analysis)
    test_db.commit()

    # 3. Create IKE Session and Message
    session = IkeSessionModel(
        analysis_id=analysis.id,
        version=2,
        spi_i="0102030405060708",
        spi_r="0807060504030201",
        initiator_ip="192.168.1.10",
        responder_ip="192.168.1.1",
        natt=False,
        first_ts=100.0,
        last_ts=102.5,
        outcome="established_observed",
    )
    test_db.add(session)
    test_db.commit()

    msg = IkeMessageModel(
        session_id=session.id,
        analysis_id=analysis.id,
        packet_no=1,
        ts=100.0,
        direction="i2r",
        exchange_type=34,
        flags=0x08,
        message_id=0,
        length=280,
    )
    test_db.add(msg)

    # 4. Create IPsec Flow
    flow = IpsecFlowModel(
        analysis_id=analysis.id,
        proto="esp",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        spi="0x12345678",
        encap="raw",
        first_ts=103.0,
        last_ts=105.0,
        packets=50,
        bytes=4000,
    )
    test_db.add(flow)

    # 5. Create Finding and Evidence
    finding = FindingModel(
        analysis_id=analysis.id,
        rule_id="CRY-DH-001",
        origin="rule",
        category="Cryptography",
        title="Weak Diffie-Hellman Group",
        severity="High",
        risk_score=80.0,
        impact=4,
        likelihood=5,
        confidence=1.0,
        explanation="Group 2 is deprecated",
        why_this_matters="Vulnerable to cryptanalysis",
        fingerprint="dh2_selected",
    )
    test_db.add(finding)
    test_db.commit()

    evidence = EvidenceModel(
        finding_id=finding.id,
        packet_no=1,
        ts=100.0,
        message="Offered DH group 2",
        field_path="proposals[0].transforms[3]",
        hex_excerpt="00040002",
    )
    test_db.add(evidence)

    # 6. Create Anomaly, IOC, Report, Timeline
    anomaly = AnomalyWindowModel(
        analysis_id=analysis.id,
        window_start=100.0,
        window_end=110.0,
        src_ip="192.168.1.10",
        score=0.75,
        flagged=True,
    )
    test_db.add(anomaly)

    ioc = IocModel(
        analysis_id=analysis.id,
        type="spi",
        value="0x12345678",
        first_seen=103.0,
    )
    test_db.add(ioc)

    report = ReportModel(
        analysis_id=analysis.id,
        format="html",
        path="/data/reports/report.html",
        sha256="abc123",
    )
    test_db.add(report)

    event_item = TimelineEventModel(
        analysis_id=analysis.id,
        ts=100.0,
        type="ike_sa_init",
        ref_type="ike_session",
        ref_id=session.id,
        label="IKE_SA_INIT",
    )
    test_db.add(event_item)
    test_db.commit()

    # Verify counts before deletion
    assert test_db.execute(select(AnalysisModel)).scalar_one_or_none() is not None
    assert test_db.execute(select(IkeSessionModel)).scalar_one_or_none() is not None
    assert test_db.execute(select(FindingModel)).scalar_one_or_none() is not None
    assert test_db.execute(select(EvidenceModel)).scalar_one_or_none() is not None
    assert test_db.execute(select(IpsecFlowModel)).scalar_one_or_none() is not None

    # Cascade test: Deleting Upload must cascade to Analysis and all child entities
    test_db.delete(upload)
    test_db.commit()

    assert test_db.execute(select(UploadModel)).scalar_one_or_none() is None
    assert test_db.execute(select(AnalysisModel)).scalar_one_or_none() is None
    assert test_db.execute(select(IkeSessionModel)).scalar_one_or_none() is None
    assert test_db.execute(select(IkeMessageModel)).scalar_one_or_none() is None
    assert test_db.execute(select(FindingModel)).scalar_one_or_none() is None
    assert test_db.execute(select(EvidenceModel)).scalar_one_or_none() is None
    assert test_db.execute(select(IpsecFlowModel)).scalar_one_or_none() is None
    assert test_db.execute(select(AnomalyWindowModel)).scalar_one_or_none() is None
    assert test_db.execute(select(IocModel)).scalar_one_or_none() is None
    assert test_db.execute(select(ReportModel)).scalar_one_or_none() is None
    assert test_db.execute(select(TimelineEventModel)).scalar_one_or_none() is None


@pytest.mark.unit
def test_schema_compiles_for_postgresql():
    """Verify all table DDL definitions compile cleanly against the PostgreSQL dialect."""
    pg_dialect = postgresql.dialect()

    for table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=pg_dialect))
        assert len(ddl) > 0
        assert table.name.upper() in ddl or table.name in ddl
