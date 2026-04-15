## Hálózati forgalom alkalmazásszintű klasszifikációja eBPF alapú monitorozás felhasználásával.

A kiindulási alap egy korábban megvalósított eBPF-alapú hálózatmonitorozó rendszer, amely képes a hálózati forgalom valós idejű megfigyelésére, valamint flow-alapú statisztikai adatok előállítására. Ezek az adatok tartalmazzák többek között a kommunikáló végpontokat, időzítési jellemzőket, valamint különböző hálózati és QoS mutatókat.

A jelen projekt célja ezen rendszer kiterjesztése egy klasszifikációs modullal, amely képes az aggregált hálózati flow-k alkalmazásszintű kategóriákba sorolására. A vizsgált alkalmazások közé tartozik többek között a YouTube, Facebook, WhatsApp, Instagram és TikTok.

A projekt célja egy olyan módszer kidolgozása és implementálása, amely:

- kizárólag flow-alapú statisztikai jellemzők alapján működik (payload vizsgálata nélkül),
- képes különböző alkalmazásokhoz tartozó hálózati forgalom automatikus felismerésére,
- alacsony erőforrásigény mellett, CPU-alapon is futtatható,
- alkalmas valós idejű feldolgozásra.

### Pipeline

1. Adatgyűjtés
Manuálisan rögzített PCAP fájlok különböző alkalmazások használata közben.
2. Feature extraction
A PCAP fájlokból statisztikai jellemzők kinyerése (pl. csomagszám, byte mennyiség, időtartam).
3. Klasszifikáció
A kinyert jellemzők alapján különböző modellek alkalmazása:
szabályalapú megközelítés (baseline),
klasszikus gépi tanulási módszerek (pl. Random Forest, SVM).
4. Kiértékelés
A modellek teljesítményének összehasonlítása (pl. pontosság, F1-score).

A projekt célja több klasszifikációs megközelítés összehasonlítása és értékelése, nem kizárólag egyetlen modell alkalmazása.

A tanításhoz és teszteléshez használt adatok manuálisan gyűjtött PCAP fájlok, amelyek az alábbi alkalmazásokhoz tartoznak: YouTube, Facebook, WhatsApp, Instagram, TikTok.

Minden alkalmazáshoz több minta áll rendelkezésre, különböző session-ökből.

### Fájlok

#### features/extractor.py

A PCAP fájlok feldolgozását végzi, és statisztikai jellemzőket állít elő. Az előállított jellemzők közé tartozik például:

időtartam,
csomagszám,
byte mennyiség,
átlagos csomagméret,
adatátviteli sebesség.

#### utils.py

A dataset összeállításáért felelős:

beolvassa a PCAP fájlokat,
meghívja a feature extraction modult,
előállítja a tanító adatokat (feature vektorok és címkék).

#### models/random_forest.py

Random Forest alapú klasszifikációs modell implementációja. A modell alkalmas nemlineáris összefüggések kezelésére, és jól alkalmazható flow-alapú statisztikai adatok esetén.

#### models/rule_based.py

Egyszerű, szabályalapú klasszifikációs megközelítés, amely baseline-ként szolgál a gépi tanulási modellek összehasonlításához.

#### models/svm.py

Support Vector Machine (SVM) alapú modell, amely alternatív klasszifikációs módszerként kerül alkalmazásra.

#### evaluation/metrics.py

A modellek teljesítményének kiértékelésére szolgáló modul. A kiértékelés során használt metrikák:

accuracy,
precision,
recall,
F1-score.

#### main.py

A teljes feldolgozási lánc belépési pontja:

dataset betöltése,
tanító és teszt adatok szétválasztása,
modell tanítása,
kiértékelés végrehajtása.

### Futtatás

A szükséges függőségek telepítése:

pip install scapy scikit-learn pandas numpy

A program futtatása:

python main.py

### Mi van hátra

feature engineering kidolgozása - a jelenlegi egyszerű jellemzők bővítése (pl. irányarány, inter-arrival time, eloszlások), ezek hatásának vizsgálata

dataset tisztítása és kiegyensúlyozása - hibás vagy zajos minták kiszűrése, mintaszámok kiegyenlítése

több modell implementálása és összehasonlítása - Random Forest mellett SVM és további egyszerű modellek kipróbálása

rule-based baseline finomítása – értelmes összehasonlítási alap kialakítása

hyperparameter tuning – modellek paramétereinek optimalizálása (pl. RF depth, estimators száma)

kiértékelési metrikák bővítése – confusion matrix, precision/recall, F1-score részletes elemzése

validáció külön adathalmazon – külső (pl. Telekomos) adatokon történő tesztelés

real-time működés vizsgálata – futási idő és erőforrásigény mérése

flow vs session szintű klasszifikáció vizsgálata – több flow együttes kezelése

semi-supervised megközelítések kipróbálása – címkézetlen adatok bevonása

integrációs terv készítése – illesztés a meglévő eBPF rendszerhez (adatfolyam, interfészek)

dokumentáció és diplomamunka megírása – módszertan, implementáció és eredmények részletes bemutatása