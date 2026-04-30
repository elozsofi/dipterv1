Kimenet:

PS C:\Users\Henrik\Documents\Suli\3. félév (MSc)\Diplomatervezés 1\dipterv1> python main.py 
Loading dataset...
Loaded 31 samples
Training Random Forest...
Evaluating...
Accuracy: 0.7

Classification report:

C:\Users\Henrik\AppData\Roaming\Python\Python312\site-packages\sklearn\metrics\_classification.py:1833: UndefinedMetricWarning: Precision is ill-defined and being set to 0.0 in labels with no predicted samples. Use `zero_division` parameter to control this behavior.
  _warn_prf(average, modifier, f"{metric.capitalize()} is", result.shape[0])
C:\Users\Henrik\AppData\Roaming\Python\Python312\site-packages\sklearn\metrics\_classification.py:1833: UndefinedMetricWarning: Precision is ill-defined and being set to 0.0 in labels with no predicted samples. Use `zero_division` parameter to control this behavior.
  _warn_prf(average, modifier, f"{metric.capitalize()} is", result.shape[0])
C:\Users\Henrik\AppData\Roaming\Python\Python312\site-packages\sklearn\metrics\_classification.py:1833: UndefinedMetricWarning: Precision is ill-defined and being set to 0.0 in labels with no predicted samples. Use `zero_division` parameter to control this behavior.
  _warn_prf(average, modifier, f"{metric.capitalize()} is", result.shape[0])
              precision    recall  f1-score   support

   instagram       0.50      0.50      0.50         2
      tiktok       0.67      1.00      0.80         4
    whatsapp       1.00      1.00      1.00         2
     youtube       0.00      0.00      0.00         2

    accuracy                           0.70        10
   macro avg       0.54      0.62      0.57        10
weighted avg       0.57      0.70      0.62        10



kis dataset (31 minta) → instabil eredmények
accuracy ~0.7 → nem megbízható ilyen méreten
egyes osztályok jól felismerhetők (whatsapp)
youtube teljesen felismeretlen (precision/recall = 0)
modell nem ad predikciót minden osztályra (warning)
fő probléma: feature-ek nem elég diszkriminatívak
dataset méret és eloszlás is limitáló tényező

A kísérlet során először egy Random Forest alapú klasszifikációs modell került betanításra manuálisan gyűjtött, alkalmazásonként kategorizált PCAP mintákból kinyert statisztikai jellemzők alapján. A kezdeti eredmények ~70%-os pontosságot mutatnak kis méretű teszthalmazon.

Az eredmények alapján megfigyelhető, hogy bizonyos alkalmazások (pl. WhatsApp) jól elkülöníthetők, míg mások (pl. YouTube) esetében a modell nem képes megfelelően felismerni a mintákat. Ez arra utal, hogy a jelenlegi feature készlet nem minden alkalmazás esetében tartalmaz elegendő diszkriminatív információt.

A kiértékelés során jelentkező metrika figyelmeztetések (pl. undefined precision) további jelzést adnak arra, hogy a modell egyes osztályokat nem reprezentál megfelelően, ami részben a kis mintaszámra, részben a jellemzők korlátozott kifejezőerejére vezethető vissza.



__________________________________________________
betöltött minták száma: 31
teszthalmaz mérete: 10

Random Forest accuracy: 0.70
SVM accuracy: 0.50
rule-based accuracy: 0.30

Random Forest:
    instagram: precision 0.00, recall 0.00, support 3
    tiktok: precision 1.00, recall 1.00, support 2
    whatsapp: precision 1.00, recall 1.00, support 2
    youtube: precision 0.50, recall 1.00, support 3
SVM:
    instagram: precision 0.00, recall 0.00, support 3
    tiktok: precision 0.33, recall 1.00, support 2
    whatsapp: precision 0.67, recall 1.00, support 2
    youtube: precision 1.00, recall 0.33, support 3
    több osztály esetén undefined precision warning jelent meg

-------------------------------------------------------------------
ud monitor visszajátszás:

sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up

cd dipterv1/ud_monitor/build
sudo ./mapinmap veth0 -t

sudo tcpreplay --intf1=veth1 /path/to/capture.pcap

__________________________________________

