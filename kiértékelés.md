A rendszer fejlesztése során több iterációban történt a modell tanítása és kiértékelése, amelyek célja a feature extraction pipeline validálása, a modellek viselkedésének megértése, valamint a teljesítmény fokozatos javítása volt. Az alábbiakban a legfontosabb futások és azok eredményei kerülnek bemutatásra.

# Első futás

Az első sikeres futás során a rendszer már képes volt a teljes dataset (36 json rekord az alkalmazások különböző usecase-eiről) feldolgozására, amely ~1700 mintát tartalmazott. A tanító és teszt halmaz 80/20 arányban került felosztásra, így a tesztkészlet mérete 343 minta volt.

A Random Forest modell ebben a fázisban megközelítőleg ~78-79%-os pontosságot ért el. A részletes kiértékelés azonban már ekkor rámutatott arra, hogy az eredmény erősen torzított. A confusion matrix alapján a modell dominánsan a „YouTube” osztályba sorolta a mintákat. Például a 215 darab YouTube minta közül 205 került helyesen besorolásra, ami ~95%-os recall értéket jelentett. Ugyanakkor az Instagram és Spotify osztályok esetében a recall érték jelentősen alacsonyabb volt (Instagram ~38%, Spotify ~15%), ami azt mutatta, hogy a modell nem képes megfelelően megkülönböztetni a hasonló jellegű forgalmakat.

A confusion matrix egy részlete jól szemlélteti ezt a problémát:

- Instagram (16 minta): 6 helyes, 9 YouTube-nak osztályozva
- Spotify (20 minta): 3 helyes, 12 YouTube-nak osztályozva
- YouTube (215 minta): 205 helyes
- TikTok (29 minta): 12 helyes, 12 YouTube-nak osztályozva
- WhatsApp (63 minta): 44 helyes

Ez alapján megállapítható volt, hogy a modell elsősorban a nagy sávszélességű, folyamatos adatfolyamokat (videó streaming) tanulta meg, míg a kisebb különbségeket nem.

Az SVM modell ebben a futásban lényegesen gyengébben teljesített, körülbelül ~61-62%-os pontosságot érve el. A confusion matrix alapján a modell gyakorlatilag a minták túlnyomó részét a YouTube osztályba sorolta, ami klasszikus jele annak, hogy a modell nem tanulta meg a döntési határokat, hanem a domináns osztályt preferálja.

# Második futás: hybrid modell bevezetése

A második iterációban bevezetésre került egy rule-based és gépi tanulást kombináló (hybrid) modell. A cél az volt, hogy bizonyos jól felismerhető mintázatok (pl. alacsony forgalmú WhatsApp kommunikáció) esetén szabályalapú döntés történjen, míg egyéb esetekben a Random Forest modell döntsön.

A futás eredménye azonban jelentős visszaesést mutatott: a hybrid modell pontossága mindössze ~18% lett. A confusion matrix alapján az összes tesztminta egyetlen osztályba (WhatsApp) került besorolásra:

- Instagram (16 minta): 16 → WhatsApp
- Spotify (20 minta): 20 → WhatsApp
- YouTube (215 minta): 215 → WhatsApp
- TikTok (29 minta): 29 → WhatsApp
- WhatsApp (63 minta): 63 → WhatsApp

Ez egyértelműen jelezte, hogy a szabályalapú komponens minden esetben aktiválódik, és teljes mértékben felülírja a gépi tanulási modell döntéseit. A hiba oka az volt, hogy a rule-based classifier túl általános feltételeket használt, így gyakorlatilag minden bemenetre érvényesült.

# Harmadik futás

A harmadik futás során a hybrid modell hibájának azonosítása után a Random Forest és SVM modellek kerültek ismételten kiértékelésre, részletesebb elemzéssel.

A Random Forest modell stabilan ~78.7%-os pontosságot ért el a 343 elemű teszthalmazon. Az osztályonkénti teljesítmény a következőképpen alakult:

- YouTube: precision ~0.80, recall ~0.95, f1-score ~0.87
- WhatsApp: precision ~0.85, recall ~0.70, f1-score ~0.77
- TikTok: precision ~0.75, recall ~0.41
- Instagram: precision ~0.46, recall ~0.38
- Spotify: precision ~0.43, recall ~0.15

Ez az eloszlás megerősítette a korábbi megfigyeléseket: a modell jól teljesít a markánsan eltérő forgalmi mintázatok esetén, azonban gyenge az egymáshoz hasonló alkalmazások megkülönböztetésében.

A feature importance elemzés további fontos információkat szolgáltatott. A legfontosabb jellemzők között szerepelt a célport (feature 19, ~0.13 súly), valamint az SNI hossz (feature 21, ~0.22 súly), ami azt mutatja, hogy a TLS metaadatok kiemelt szerepet játszanak a klasszifikációban. Ezzel szemben több feature (pl. jitter, RTT) gyakorlatilag 0 fontosságú volt, így ezek hozzájárulása elhanyagolható.

Az SVM modell ebben a futásban is gyenge maradt (~61.8% pontosság), és továbbra is erősen torzított predikciókat adott, ami megerősítette, hogy ebben a problématérben a Random Forest alkalmasabb választás.

# Következtetések

A több iteráción keresztül végzett kísérletek alapján egyértelműen megállapítható, hogy a rendszer alapvetően működőképes, és képes titkosított hálózati forgalom alapján alkalmazásszintű klasszifikációt végezni. A Random Forest modell közel 80%-os pontossága ezt alátámasztja.

Három fő probléma azonosítható:

Osztály imbalance: a domináns osztály (YouTube) torzítja a tanulást
Feature korlátok: a jelenlegi jellemzők nem elegendőek a hasonló alkalmazások elkülönítésére
Hybrid modell hibás implementációja: a rule-based komponens túl domináns

következő lépések a feature space bővítése, az osztályok kiegyensúlyozása, valamint a hybrid modell újratervezése olyan módon, hogy a szabályalapú és a tanult komponensek egymást kiegészítve működjenek.

# Negyedik futás

A negyedik futás során a dataset további bővítése történt meg. Az új mérési állományok között már több különböző felhasználási szcenárió is szerepelt (podcast hallgatás, videóban történő ugrálás, zenelejátszás, livestream, TikTok scrolling, Instagram story, reels, WhatsApp hívások, üzenetküldés). Összesen 313 darab tesztminta volt.

Ebben az iterációban a rule-based modell viselkedése jelentősen javult az előző futáshoz képest. Míg korábban a rl gyakorlatilag minden mintát a WhatsApp osztályba sorolt, addig ebben a futásban már több osztály között próbált különbséget tenni. A modell pontossága ~15.6%-ra növekedett.

A confusion matrix alapján azonban továbbra is megfigyelhető volt, hogy a szabályrendszer erősen torzít a WhatsApp irányába:

Instagram: 15 mintából 8 került WhatsApp kategóriába
Spotify: 125 mintából 86 került WhatsApp kategóriába
YouTube: 114 mintából 79 került WhatsApp kategóriába
TikTok: 25 mintából 20 került WhatsApp kategóriába

Ugyanakkor a rendszer már nem kizárólag egyetlen osztályt használt, hanem bizonyos esetekben képes volt helyes döntések meghozatalára is. Például a WhatsApp osztály esetén 34 mintából 25 került helyesen besorolásra (~74%-os recall). Ez arra utal, hogy a szabályalapú komponens bizonyos karakterisztikus mintázatokat már képes felismerni, azonban a szabályok továbbra is túl általánosak.

A hybrid modell ebben a futásban jelentős javulást mutatott, és ~62.9%-os pontosságot ért el. Érdekes megfigyelés volt, hogy a hybrid modell és a Random Forest modell gyakorlatilag teljesen azonos eredményt adott. Ez arra utal, hogy a hibrid architektúrában a szabályalapú komponens ritkán aktiválódott, vagy a döntések túlnyomó részében a Random Forest modell eredménye került felhasználásra.

A Random Forest modell stabil teljesítményt nyújtott:

pontosság: ~62.9%
macro average f1-score: ~0.59
weighted average f1-score: ~0.62

Az osztályonkénti eredmények a következőképpen alakultak:

Instagram: precision ~0.69, recall ~0.60
Spotify: precision ~0.66, recall ~0.74
YouTube: precision ~0.56, recall ~0.62
TikTok: precision ~0.80, recall ~0.32
WhatsApp: precision ~0.67, recall ~0.47

A confusion matrix alapján a legnagyobb problémát továbbra is a Spotify és YouTube osztályok elkülönítése jelentette:

Spotify minták közül 28 került YouTube kategóriába
YouTube minták közül 35 került Spotify kategóriába

Ez arra utal, hogy a két alkalmazás hálózati mintázata bizonyos use-case-ek esetén erősen hasonló. Mindkét alkalmazás folyamatos média streaminget használ, ezért a jelenlegi feature space nem biztosít elegendő információt a pontos elkülönítéshez.

A TikTok osztály esetén magas precision (~0.80), de alacsony recall (~0.32) figyelhető meg. Ez azt jelenti, hogy amikor a modell TikTok kategóriát prediktál, az általában helyes, azonban a TikTok minták jelentős részét más osztályokba sorolja.

Az SVM modell teljesítménye ebben az iterációban is jelentősen elmaradt a Random Forest mögött. A modell ~46.6%-os pontosságot ért el, és a confusion matrix alapján továbbra is erősen a YouTube osztály felé torzított. Például:

Spotify: 125 mintából 85 került YouTube kategóriába
TikTok: 25 mintából 22 került YouTube kategóriába

Ez megerősítette, hogy az SVM modell ebben a problématérben nem képes megfelelő döntési határok kialakítására.

A feature importance elemzés további fontos eredményeket mutatott. A legfontosabb feature továbbra is a célport feature volt (~0.22 súly), amely jelentős mértékben dominálta a döntési folyamatot. Emellett több másik feature is relevánssá vált:

avg_pkt_size: ~0.090
variance_proxy: ~0.091
rx_bytes: ~0.084
total_bytes: ~0.084
duration: ~0.075

Fontos megfigyelés volt, hogy a korábban teljesen inaktív feature-ök közül néhány már nem nulla fontosságot kapott:

sni_present: ~0.008
sni_length: ~0.031

Ez arra utal, hogy a feature extraction pipeline javítása sikeres volt, és ezek a jellemzők már ténylegesen hordoznak információt a klasszifikáció során.

A negyedik futás eredményei alapján megállapítható, hogy a rendszer stabilizálódott, és a Random Forest modell konzisztensen a legjobb teljesítményt nyújtja. A rule-based komponens működése javult, azonban önálló klasszifikációra továbbra sem alkalmas. A fő kihívást jelenleg az egymáshoz hasonló média streaming alkalmazások (különösen Spotify és YouTube) elkülönítése jelenti, amely várhatóan további feature engineering és adatbővítés segítségével javítható.

# Ötödik futás

Az ötödik futás során a rendszer további finomhangolása történt meg, elsősorban a rule-based komponens szabályrendszerének átdolgozásával, valamint a hybrid architektúra módosításával. A dataset ebben a futásban összesen 289 tesztmintát tartalmazott, amelyek között továbbra is megtalálhatók voltak különböző média streaming, short-video, üzenetküldési és hívási use-case-ek.

A Random Forest modell esetében bevezetésre került az out-of-bag (OOB) kiértékelés is, amely ~52.9%-os értéket adott. Ez közel megegyezett a teszthalmazon mért ~51.9%-os pontossággal, ami arra utal, hogy a modell generalizációs képessége stabil, és jelentős overfitting nem figyelhető meg.

A rule-based modell ebben az iterációban jelentős fejlődést mutatott. A pontosság ~39.8%-ra növekedett, amely lényeges javulás a korábbi ~15.6%-hoz képest. Ez azt mutatja, hogy az új szabályok (különösen az SNI, port és forgalmi mintázatok alapján történő döntések) már ténylegesen képesek hasznos információt szolgáltatni.

A confusion matrix alapján ugyanakkor továbbra is erős torzítás figyelhető meg a YouTube osztály irányába:

Instagram: 13 mintából 12 került YouTube kategóriába
Spotify: 108 mintából 84 került YouTube kategóriába
TikTok: 24 mintából 21 került YouTube kategóriába
WhatsApp: 27 mintából 19 került YouTube kategóriába

Ennek ellenére fontos előrelépés volt, hogy a rendszer már több különböző osztályban is képes helyes predikciókra. Különösen érdekes eredmény született a TikTok osztály esetében, ahol a precision érték ~1.00 lett, miközben a recall továbbra is alacsony (~0.04) maradt. Ez azt jelenti, hogy amikor a rendszer TikTok kategóriát prediktált, az szinte minden esetben helyes volt, azonban a TikTok minták túlnyomó részét továbbra is más osztályokba sorolta. Ez arra utal, hogy a TikTok-specifikus szabályok túl szigorúak, de alapvetően jó irányba mutatnak.

A hybrid modell tovább javult, és ~53.6%-os pontosságot ért el, amellyel enyhén meghaladta a tisztán Random Forest alapú megközelítést (~51.9%). Ez különösen fontos eredmény, mivel korábban a hybrid modell vagy teljesen hibásan működött, vagy gyakorlatilag megegyezett az RF modellel. Ebben a futásban már egyértelműen láthatóvá vált, hogy a szabályalapú komponens ténylegesen képes hozzáadott információt biztosítani a gépi tanulási modell számára.

A hybrid modell osztályonkénti eredményei:

Instagram: precision ~0.50, recall ~0.08
Spotify: precision ~0.48, recall ~0.86
YouTube: precision ~0.66, recall ~0.42
TikTok: precision ~0.67, recall ~0.08
WhatsApp: precision ~0.56, recall ~0.37

A confusion matrix alapján továbbra is a Spotify és YouTube osztályok elkülönítése jelentette a legnagyobb problémát:

YouTube minták közül 64 került Spotify kategóriába
Spotify minták közül 13 került YouTube kategóriába

Ez azt mutatja, hogy a korábbi YouTube-dominancia részben megfordult, és a modell bizonyos mértékig már a Spotify osztály felé torzít. Ennek egyik oka valószínűleg az alkalmazott class weighting stratégia, amely a Spotify osztály számára nagyobb súlyt rendelt a tanítás során.

A Random Forest modell teljesítménye:

pontosság: ~51.9%
macro average f1-score: ~0.36
weighted average f1-score: ~0.48

Az osztályonkénti eredmények:

Instagram: precision ~0.50, recall ~0.08
Spotify: precision ~0.46, recall ~0.85
YouTube: precision ~0.64, recall ~0.40
TikTok: precision ~0.67, recall ~0.08
WhatsApp: precision ~0.67, recall ~0.30

Az SVM modell ebben a futásban is jelentősen gyengébben teljesített (~41.5% pontosság), és továbbra is erős YouTube torzítást mutatott. A TikTok és Instagram minták túlnyomó része ismét YouTube kategóriába került, ami megerősítette, hogy az SVM modell ebben a problématérben nem képes megfelelően kezelni a komplex, nemlineáris döntési határokat.

A feature importance elemzés alapján a legfontosabb feature továbbra is a célport (dst_port) maradt (~0.177 súly). Emellett kiemelkedő fontosságot kaptak:

avg_pkt_size: ~0.093
total_bytes: ~0.084
variance_proxy: ~0.084
bytes_per_sec: ~0.070
duration: ~0.064

Ez azt mutatja, hogy a modell döntéseit elsősorban a forgalom volumene, a csomagméretek és az időbeli mintázatok befolyásolják.

Az ötödik futás eredményei alapján megállapítható, hogy a rendszer viselkedése stabilizálódott, és a hybrid architektúra már tényleges előnyt biztosít a tisztán gépi tanulás alapú megközelítéshez képest. A rule-based komponens immár nem rontja a teljesítményt, hanem bizonyos esetekben képes javítani az RF modell döntéseit.

A negyedik futáshoz képest több fontos változás figyelhető meg:

- a rule-based modell pontossága jelentősen javult (~15.6% -> ~39.8%)
- a hybrid modell először teljesített mérhetően jobban a Random Forest modellnél
- a Spotify osztály felismerése tovább javult
- a YouTube dominancia csökkent, ugyanakkor részleges Spotify bias jelent meg

A jelenlegi eredmények alapján a rendszer legnagyobb kihívását továbbra is az egymáshoz nagyon hasonló média streaming alkalmazások elkülönítése jelenti. A további fejlesztési lehetőségek között szerepelhet a QUIC detektálás, DNS-alapú feature extraction, TLS fingerprinting (JA3), valamint időbeli burst- és flow-analízis bevezetése.