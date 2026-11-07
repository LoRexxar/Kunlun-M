import logging
import statistics

import redis
from kombu import Connection, Exchange, Producer, Queue

from core.config.config import yeti_config
from core.events.message import EventMessage, EventTypes, LogMessage

MEMORY_LIMIT_MB = yeti_config.get("events", "memory_limit", 64)
KEEP_RATIO = yeti_config.get("events", "keep_ratio", 0.9)


class EventProducer:
    def __init__(self):
        global MEMORY_LIMIT_MB, KEEP_RATIO
        self.event_producer = None
        self.log_producer = None
        self._messages_sizes = []
        if isinstance(MEMORY_LIMIT_MB, str):
            self._memory_limit = int(MEMORY_LIMIT_MB)
        else:
            self._memory_limit = MEMORY_LIMIT_MB
        if self._memory_limit < 64:
            logging.warning(
                f"events.memory_limit <{self._memory_limit}> is invalid. Must be >= 64 fallback to 64"
            )
            self._memory_limit = 64
        self._memory_limit = self._memory_limit * 1024 * 1024
        if isinstance(KEEP_RATIO, str):
            self._keep_ratio = float(KEEP_RATIO)
        else:
            self._keep_ratio = KEEP_RATIO
        if self._keep_ratio > 0 and self._keep_ratio < 1:
            self._keep_ratio = self._keep_ratio
        else:
            self._keep_ratio = 0.9
            logging.warning(
                f"events.keep_ratio <{self._keep_ratio}> is invalid. Must be > 0 and < 1 fallback to 0.9"
            )
        try:
            self.conn = Connection(f"redis://{yeti_config.get('redis', 'host')}/")
            self.channel = self.conn.channel()
            self._redis_client = redis.from_url(
                f"redis://{yeti_config.get('redis', 'host')}/"
            )
            self.create_event_producer()
            self.create_log_producer()
        except Exception as e:
            logging.exception(f"Error creating producers: {e}")

    def create_event_producer(self):
        self.event_exchange = Exchange("events", type="direct")
        self.event_producer = Producer(
            exchange=self.event_exchange,
            channel=self.channel,
            routing_key="events",
            serializer="json",
        )
        self.event_queue = Queue(
            name="events", exchange=self.event_exchange, routing_key="events"
        )
        self.event_queue.maybe_bind(self.conn)
        self.event_queue.declare()

    def create_log_producer(self):
        self.log_exchange = Exchange("logs", type="direct")
        self.log_producer = Producer(
            exchange=self.log_exchange,
            channel=self.channel,
            routing_key="logs",
            serializer="json",
        )
        self.log_queue = Queue(
            name="logs", exchange=self.log_exchange, routing_key="logs"
        )
        self.log_queue.maybe_bind(self.conn)
        self.log_queue.declare()

    def _trim_queue_size(self, key: str) -> bool:
        memory_usage = self._redis_client.memory_usage(key) or 0
        if memory_usage > self._memory_limit:
            queue_size = self._redis_client.llen(key)
            end_index = int(queue_size * self._keep_ratio)
            trimmed_events = queue_size - end_index
            logging.warning(
                f"Removing {trimmed_events} oldest elements from queue <{key}>"
            )
            self._redis_client.ltrim(key, 0, end_index)
            return True
        return False

    # Message is validated on consumer end
    def publish_event(self, event: EventTypes):
        if not self.event_producer:
            return
        try:
            message = EventMessage(event=event)
            self.event_producer.publish(message.model_dump_json())
            self._trim_queue_size("events")
        except Exception:
            logging.exception("Error publishing event")

    def publish_log(self, log: str | dict):
        if not self.log_producer:
            return
        try:
            message = LogMessage(log=log)
            self.log_producer.publish(message.model_dump_json())
            self._trim_queue_size("logs")
        except Exception:
            logging.exception("Error publishing log")


producer = EventProducer()
