"""Security-focused audit-chain tampering tests."""

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from audit_log import create_audit_entry, verify_audit_chain
from models import AuditLog, Base


class AuditChainSecurityTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine)()
        for index in range(5):
            create_audit_entry(
                event_id=None,
                actor="operator",
                action="test",
                before_state=None,
                after_state={"index": index},
                reasoning="security test",
                session=self.session,
            )

    def tearDown(self):
        self.session.close()

    def test_latest_depth_checks_latest_entries(self):
        latest = self.session.query(AuditLog).order_by(AuditLog.id.desc()).first()
        latest.reasoning = "tampered"
        self.session.commit()
        self.assertFalse(verify_audit_chain(self.session, depth=2))

    def test_old_entry_modification_is_detected(self):
        entry = self.session.query(AuditLog).filter_by(id=2).one()
        entry.reasoning = "tampered old entry"
        self.session.commit()
        self.assertFalse(verify_audit_chain(self.session))

    def test_prev_hash_modification_is_detected(self):
        entry = self.session.query(AuditLog).filter_by(id=3).one()
        entry.prev_hash = "0" * 64
        self.session.commit()
        self.assertFalse(verify_audit_chain(self.session))

    def test_entry_hash_modification_is_detected(self):
        entry = self.session.query(AuditLog).filter_by(id=4).one()
        entry.entry_hash = "f" * 64
        self.session.commit()
        self.assertFalse(verify_audit_chain(self.session))

    def test_deleted_entry_is_detected(self):
        entry = self.session.query(AuditLog).filter_by(id=3).one()
        self.session.delete(entry)
        self.session.commit()
        self.assertFalse(verify_audit_chain(self.session))

    def test_deleted_latest_entry_is_detected_by_anchor(self):
        entry = self.session.query(AuditLog).order_by(AuditLog.id.desc()).first()
        self.session.delete(entry)
        self.session.commit()
        self.assertFalse(verify_audit_chain(self.session))

    def test_reordered_content_is_detected(self):
        first = self.session.query(AuditLog).filter_by(id=2).one()
        second = self.session.query(AuditLog).filter_by(id=3).one()
        first.after_state, second.after_state = second.after_state, first.after_state
        self.session.commit()
        self.assertFalse(verify_audit_chain(self.session))

    def test_event_reassignment_is_detected(self):
        entry = self.session.query(AuditLog).filter_by(id=3).one()
        entry.event_id = 999
        self.session.commit()
        self.assertFalse(verify_audit_chain(self.session))


if __name__ == "__main__":
    unittest.main()
