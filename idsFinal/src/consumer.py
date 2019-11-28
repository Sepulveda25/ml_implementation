from kafka import KafkaConsumer
from json import dumps
import pickle

consumer = KafkaConsumer('test-topic',
                        group_id='test-consumer',
                        bootstrap_servers=['kafka:9092'])

for message in consumer:
    message = message.value
    print('{} added'.format(message))