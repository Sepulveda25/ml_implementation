import os
import pickle
import numpy as np
import pandas as pd
import datetime
from kafka import KafkaConsumer
from sklearn import preprocessing

# Nuevo dataset
"""features = ["Tot Bwd Pkts", "Fwd Pkt Len Min", "Flow Duration", "Fwd Pkt Len Std", "Flow IAT Std", "Bwd Pkt Len Std", "Fwd Pkt Len Max",
    "Flow IAT Max", "Flow Pkts/s", "Flow IAT Min", "TotLen Fwd Pkts", "Bwd Pkt Len Max", "Fwd IAT Tot", "Flow Byts/s"]"""

# Ultimo dataset
"""features = ["Flow Byts/s", "Flow IAT Mean", "Flow Duration", "Flow IAT Std", "Fwd Pkt Len Max", "Flow IAT Max", "Flow Pkts/s",
"Tot Bwd Pkts", "Fwd IAT Tot", "Flow IAT Min", "Bwd Pkt Len Std", "Fwd Pkt Len Std", "TotLen Bwd Pkts", "Bwd Pkt Len Max"]"""

# Dataset final con Feature Extraccion:  Importancia de la característica
"""features = ["Flow IAT Mean", "Flow IAT Max", "Flow Duration", "Flow Pkts/s", "Flow IAT Std", "Fwd IAT Tot", "Fwd Pkt Len Max", "TotLen Fwd Pkts"
, "Flow Byts/s", "TotLen Bwd Pkts", "Tot Fwd Pkts", "Bwd Pkt Len Mean", "Flow IAT Min"]"""

# Dataset final con Feature Extraccion: Eliminación de características recursivas
features = ["Flow Duration", "Bwd Pkt Len Std", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Bwd IAT Std", "Pkt Len Std",
"PSH Flag Cnt", "Down/Up Ratio", "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Seg Size Min"]

#no_existe = True
primera_vez = True
psList = []
sqlList = []
sshList = []
dosList = []
aBorrar = []

class Consumer(object):

    def __init__(self):

        self.cur_path = os.path.dirname(__file__)

#        logging.basicConfig(format='%(asctime)s %(iporigen)s %(ipdestino)s %(ataque)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename = "alert.log")
        self.log = open("/home/debianml/idsFinal/alert.log", "a")

    def hacer_prediccion(self, model, dataframe):

        print("---------------")
        print("\n")
        global no_existe
        dataframe = dataframe.iloc[1:]
        df = pd.DataFrame(dataframe)
        dfCompleto = pd.DataFrame(dataframe)
        df = df.loc[:, features]
        df = df.fillna(0)

#        Descomentar si Flow Byts esta en la lista de features
        """df["Flow Byts/s"]=df["Flow Byts/s"].replace('Infinity', -1)
        number_list=[]
        for j in df["Flow Byts/s"]:
            try:
                num=int(float(j))
                number_list.append(int(num))
            except:
                number_list.append(j)
        df["Flow Byts/s"]=number_list"""

        string_features=[]
        for k in features:
            if df[k].dtype=="object":
                string_features.append(k)

        labelencoder_X = preprocessing.LabelEncoder()
        for l in string_features:
            try:
                df[l]=labelencoder_X.fit_transform(df[l])
            except:
                df[l]=df[l].replace('Infinity', -1)

        dfCompleto["Label"] = model.predict(df)

#        print(dfCompleto)

        """if no_existe:
            dfCompleto.to_csv('Pues.csv' ,index = False)
            no_existe=False
        else:
            dfCompleto.to_csv('Pues.csv' ,index = False, header=False,mode="a")"""

        self.emitir_alerta(dfCompleto)

    def emitir_alerta(self, flujos):

        global psList
        global sqlList
        global sshList
        global dosList
        global aBorrar
        global primera_vez
        newpsList = []
        newsqlList = []
        newsshList = []
        newdosList = []

        for index, row in flujos.iterrows():
            if (row["Label"] != "BENIGN"):
                if not row["Flow ID"].startswith("200.16"):
                    if (row["Label"] == "Port Scan"):
                        newpsList.append(row["Flow ID"].split('-')[0] + "-" + row["Flow ID"].split('-')[1])
                        psList.append(row["Flow ID"].split('-')[0] + "-" + row["Flow ID"].split('-')[1])
                    elif (row["Label"] == "SQL Injection"):
                        newsqlList.append(row["Flow ID"].split('-')[0] + "-" + row["Flow ID"].split('-')[1])
                        sqlList.append(row["Flow ID"].split('-')[0] + "-" + row["Flow ID"].split('-')[1])
                    elif (row["Label"] == "SSH Fuerza Bruta"):
                        newsshList.append(row["Flow ID"].split('-')[0] + "-" + row["Flow ID"].split('-')[1])
                        sshList.append(row["Flow ID"].split('-')[0] + "-" + row["Flow ID"].split('-')[1])
                    elif (row["Label"] == "Ataque DoS"):
                        newdosList.append(row["Flow ID"].split('-')[0] + "-" + row["Flow ID"].split('-')[1])
                        dosList.append(row["Flow ID"].split('-')[0] + "-" + row["Flow ID"].split('-')[1])

        psCount = [psList.count(p) for p in psList]
        psDicc = dict(zip(psList, psCount))
        sqlCount = [sqlList.count(p) for p in sqlList]
        sqlDicc = dict(zip(sqlList, sqlCount))
        sshCount = [sshList.count(p) for p in sshList]
        sshDicc = dict(zip(sshList, sshCount))
        dosCount = [dosList.count(p) for p in dosList]
        dosDicc = dict(zip(dosList, dosCount))

        for ID, frec in psDicc.items():
            if (frec > 5):
                IPS = ID.split('-')
                print ("Ataque de ESCANEO DE PUERTOS detectado desde la IP " + IPS[0] + " a la IP " + IPS[1]+ "\n")
#                logging.warning("Ataque de ESCANEO DE PUERTOS detectado desde la IP " + IPS[0] + " a la IP " + IPS[1]+ "\n")
                self.log.write(str(datetime.datetime.now().isoformat()) + " " + IPS[0] + " " + IPS[1] + " Priority: 1" + " - TCP - " + "[Port Scan] detectado \n")
        for ID, frec in sqlDicc.items():
            if (frec > 1):
                IPS = ID.split('-')
                print ("Ataque de INYECCION SQL detectado desde la IP " + IPS[0] + " a la IP " + IPS[1]+ "\n")
                self.log.write(str(datetime.datetime.now().isoformat()) + " " + IPS[0] + " " + IPS[1] + " Priority: 1" + " - TCP - " + "[SQL Injection] detectado \n")
        for ID, frec in sshDicc.items():
            if (frec > 1):
                IPS = ID.split('-')
                print ("Ataque de FUERZA BRUTA DE ACCESO SSH detectado desde la IP " + IPS[0] + " a la IP " + IPS[1]+ "\n")
                self.log.write(str(datetime.datetime.now().isoformat()) + " " + IPS[0] + " " + IPS[1] + " Priority: 1" + " - TCP - " + "[SSH Fuerza bruta] detectado \n")
        for ID, frec in dosDicc.items():
            if (frec > 1):
                IPS = ID.split('-')
                print ("Ataque de DENEGACION DE SERVICIO detectado desde la IP " + IPS[0] + " a la IP " + IPS[1]+ "\n")
                self.log.write(str(datetime.datetime.now().isoformat()) + " " + IPS[0] + " " + IPS[1] + " Priority: 1" + " - TCP - " + "[Ataque DoS] detectado \n")

#        print ("New psList: " + str(len(newpsList)) + " psList: " + str(len(psList)) + "\n")
#        print ("New sqlList: " + str(len(newsqlList)) + " sqlList: " + str(len(sqlList)) + "\n")
#        print ("New sshList: " + str(len(newsshList)) + " sshList: " + str(len(sshList)) + "\n")
#        print ("New dosList: " + str(len(newdosList)) + " dosList: " + str(len(dosList)) + "\n")

        if (primera_vez == True):
            aBorrar = [len(newpsList), len(newsqlList), len(newsshList), len(newdosList)]
            primera_vez = False
        else:
            del psList[:aBorrar[0]]
            del sqlList[:aBorrar[1]]
            del sshList[:aBorrar[2]]
            del dosList[:aBorrar[3]]
            aBorrar = [len(newpsList), len(newsqlList), len(newsshList), len(newdosList)]


    def kafka_setup(self):

        # Se conecta a test-topic
        consumer = KafkaConsumer('test-topic',
                                 group_id='test-consumer',
                                 bootstrap_servers=['kafka:9092'])

        filename = "/home/debianml/idsFinal/modelo_ultimo_newfeatures.sav"
        model = pickle.load(open(filename, 'rb'))

        for message in consumer:
            self.hacer_prediccion(model, pickle.loads(message.value))

        # consume earliest available messages, don't commit offsets
        KafkaConsumer(auto_offset_reset='earliest', enable_auto_commit=False)

        # StopIteration if no message after 1sec
        KafkaConsumer(consumer_timeout_ms=1000)


if __name__ == '__main__':
    consumer = Consumer()
    consumer.kafka_setup()
