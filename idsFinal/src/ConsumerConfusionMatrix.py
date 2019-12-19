import os
import pickle
import numpy as np
import pandas as pd
from kafka import KafkaConsumer
from sklearn import preprocessing

import matplotlib
matplotlib.use('TkAgg')
from matplotlib import pyplot as plt
from sklearn.metrics import confusion_matrix
import itertools


# Nuevo dataset
"""features = ["Tot Bwd Pkts", "Fwd Pkt Len Min", "Flow Duration", "Fwd Pkt Len Std", "Flow IAT Std", "Bwd Pkt Len Std", "Fwd Pkt Len Max",
    "Flow IAT Max", "Flow Pkts/s", "Flow IAT Min", "TotLen Fwd Pkts", "Bwd Pkt Len Max", "Fwd IAT Tot", "Flow Byts/s"]"""

# Ultimo dataset
"""features = ["Flow Byts/s", "Flow IAT Mean", "Flow Duration", "Flow IAT Std", "Fwd Pkt Len Max", "Flow IAT Max", "Flow Pkts/s",
"Tot Bwd Pkts", "Fwd IAT Tot", "Flow IAT Min", "Bwd Pkt Len Std", "Fwd Pkt Len Std", "TotLen Bwd Pkts", "Bwd Pkt Len Max"]"""

# Dataset final con Feature Extraccion:  Importancia de la característica
"""features = ["Flow IAT Mean", "Flow IAT Max", "Flow Duration", "Flow Pkts/s", "Flow IAT Std", "Fwd IAT Tot", "Fwd Pkt Len Max", "TotLen Fwd $
, "Flow Byts/s", "TotLen Bwd Pkts", "Tot Fwd Pkts", "Bwd Pkt Len Mean", "Flow IAT Min"]"""

# Dataset final con Feature Extraccion: Eliminación de características recursivas
features = ["Flow Duration", "Bwd Pkt Len Std", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Bwd IAT Std", "Pkt Len Std",
"PSH Flag Cnt", "Down/Up Ratio", "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Seg Size Min"]

no_existe = True

y_labels = ['Ataque DoS', 'BENIGN', 'Port Scan', 'SQL Injection', 'SSH Fuerza Bruta']

def plot_confusion_matrix(cm,
                          target_names,
                          title,
                          cmap=plt.cm.Blues,
                          normalize=None):

    accuracy = np.trace(cm) / float(np.sum(cm))
    misclass = 1 - accuracy

    if cmap is None:
        cmap = plt.get_cmap('Blues')

    plt.figure(figsize=(8, 6))
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()

    if target_names is not None:
        tick_marks = np.arange(len(target_names))
        plt.xticks(tick_marks, target_names, rotation=45)
        plt.yticks(tick_marks, target_names)

    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]


    thresh = cm.max() / 1.5 if normalize else cm.max() / 2
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        if normalize:
            plt.text(j, i, "{:0.4f}".format(cm[i, j]),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black")
        else:
            plt.text(j, i, "{:,}".format(cm[i, j]),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black")


    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label\naccuracy={:0.4f}; misclass={:0.4f}'.format(accuracy, misclass))
    plt.show()

def etiquetar(df2):

    if (df2["Src IP"] == "172.16.81.5"):
        return "SSH Fuerza Bruta"
    else:
        return "BENIGN"

class Consumer(object):

    def __init__(self):
        """__init__ method for first initialization from config"""
        self.cur_path = os.path.dirname(__file__)


    def hacer_prediccion(self, model, dataframe):

        print("---------------")

        global no_existe
        dataframe = dataframe.iloc[1:]
        df = pd.DataFrame(dataframe)
        dfCompleto = pd.DataFrame(dataframe)
        df = df.loc[:, features]
        df = df.fillna(0)

#        df["Flow Byts/s"]=df["Flow Byts/s"].replace('Infinity', -1)
#        number_list=[]
#        for j in df["Flow Byts/s"]:
#            try:
#                num=int(float(j))
#                number_list.append(int(num))
#            except:
#                number_list.append(j)
#        df["Flow Byts/s"]=number_list

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

        y = dfCompleto.apply(etiquetar, axis = 1)
#        dfCompleto["Label"] = dfCompleto["Src IP"].apply(lambda x: "SQL Injection" if x == "172.16.81.6" else "BENIGN")
#        dfCompleto["Label"] = dfCompleto["Dst IP"].apply(lambda x: "SQL Injection" if x == "172.16.81.6" else)
#        y = dfCompleto["Label"]
        dfCompleto["Label"] = model.predict(df)
        predict = dfCompleto["Label"]

        """if no_existe:
            dfCompleto.to_csv('pruebaconteoips.csv' ,index = False)
            no_existe=False
        else:
            dfCompleto.to_csv('pruebaconteoips.csv' ,index = False, header=False,mode="a")"""

        cm = confusion_matrix(y, predict)
        plot_confusion_matrix(cm, y_labels, "Matriz de confusion del modelo")


    def kafka_setup(self):
        """kafka_setup func to setup up message broker for receives data"""
        # To consume latest messages and auto-commit offsets
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
