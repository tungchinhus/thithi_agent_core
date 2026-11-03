import pytest

from thithi.gateway.labels import CloudPolicy, Label, LabelPolicy


def test_known_sources(policy):
    assert policy.classify_source("erp.ar_aging").label == Label.MAT
    assert policy.classify_source("docs.quy_che/nghi_phep.docx").label == Label.NOI_BO
    hr = policy.classify_source("hrm.payroll")
    assert hr.label == Label.TOI_MAT and not hr.cloud_allowed


def test_unknown_source_defaults_to_mat(policy):
    c = policy.classify_source("something.new")
    assert c.label == Label.MAT and c.allow_cloud == CloudPolicy.MASKED


def test_mixed_payload_takes_strictest(policy):
    c = policy.classify(["docs.public/a.pdf", "erp.ar_aging", "hrm.payroll"])
    assert c.label == Label.TOI_MAT and c.allow_cloud == CloudPolicy.NEVER
    c = policy.classify(["docs.public/a.pdf", "erp.revenue_summary"])
    assert c.label == Label.NOI_BO and c.allow_cloud == CloudPolicy.MASKED


def test_toi_mat_cannot_be_sent(tmp_path):
    p = tmp_path / "labels.yaml"
    p.write_text("sources:\n  hrm.*: {label: toi_mat, allow_cloud: masked}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        LabelPolicy.from_yaml(p)
