from time import sleep
from json import dumps
import pickle
from kafka import KafkaProducer

producer = KafkaProducer(bootstrap_servers='kafka:9092',
                              client_id='test-producer',
                              max_request_size=30000000)

for e in range(1000):
    data = {'number' : e}
    byte_array = pickle.dumps(data)
    producer.send('test-topic', value=byte_array)
    sleep(5)