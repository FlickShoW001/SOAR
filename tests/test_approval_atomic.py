"""Atomic approval claim regression test."""

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Approval, Base, Decision, Event


class AtomicApprovalTests(unittest.TestCase):
    def test_only_one_reviewer_can_claim_pending_event(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        sessions = sessionmaker(bind=engine)

        setup = sessions()
        event = Event(
            source_ip="192.168.1.20",
            event_type="test",
            severity=5,
            raw_log_line="test",
            status="pending_approval",
        )
        setup.add(event)
        setup.flush()
        decision = Decision(
            event_id=event.id,
            action="block",
            confidence=1.0,
            risk_score=100.0,
            requires_approval=True,
            reasoning="{}",
        )
        setup.add(decision)
        setup.commit()

        first = sessions()
        second = sessions()
        first_claim = (
            first.query(Event)
            .filter(Event.id == event.id, Event.status == "pending_approval")
            .update({Event.status: "responding"}, synchronize_session=False)
        )
        first.add(
            Approval(event_id=event.id, decision_id=decision.id, status="approved")
        )
        first.commit()

        second_claim = (
            second.query(Event)
            .filter(Event.id == event.id, Event.status == "pending_approval")
            .update({Event.status: "responding"}, synchronize_session=False)
        )
        second.rollback()

        self.assertEqual(first_claim, 1)
        self.assertEqual(second_claim, 0)
        self.assertEqual(setup.query(Approval).filter_by(event_id=event.id).count(), 1)
        first.close()
        second.close()
        setup.close()


if __name__ == "__main__":
    unittest.main()
