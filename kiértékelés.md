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