# First Class API Design

**Status: ZÁVAZNÝ NÁVRHOVÝ KONTRAKT**  
Verze: 1.0  
Datum: 2026-10-23  
Rozsah: skriptovací API Spideru, Parts, editace, commit, hold a jejich prezentace.

Tento dokument určuje cílovou architekturu First Class API. Implementace,
generovaná dokumentace, editor i testy se s ním musí shodovat. Odchylka vyžaduje
výslovně schválenou změnu kontraktu; nesmí vzniknout potichu jako implementační
zkratka. Závaznost návrhu neznamená, že jsou všechny jeho části implementované.

Slova **musí**, **nesmí** a **má** označují závazné požadavky. Otevřená rozhodnutí
jsou uvedena samostatně a nesmějí být vydávána za hotový kontrakt.

## Základní filozofie

Pracujeme s **Parts**: částmi obsahu, které si nesou svůj význam, reprezentaci
a vazby na původní přenosová data. Stejná abstrakce slouží ke čtení, úpravě,
sestavení i čekání na další callback. Hold prodlužuje životnost části, nikoli
jen anonymních bajtů.

API má být nízkoprahové. Uživatel má pracovat s tím, čemu Spider skutečně rozumí,
bez ručního počítání offsetů, délek a rutinního převádění reprezentací.
Neznámý obsah je přitom plnohodnotný: absence anotace není chyba.

Skripty běží na backendu i bez otevřeného GUI. Editor zná API, poskytuje typovou
nápovědu a příklady. Referenční dokumentace se generuje z definic API, aby se
nemusela nezávisle synchronizovat s implementací.

## Zpráva a seznam Parts

`api.message` je pracovní zpráva aktuálního běhu skriptu. Její `parts` zahrnují
veškerý dostupný obsah, včetně neanotovaných mezer. Po zavedení holdu může zpráva
obsahovat podržené části z předchozích callbacků před novými částmi.

Part není automaticky jedna anotace ani jeden souvislý wire slice. Anotace se
mohou překrývat; jedna interpretovaná část může mít vazbu na více wire rozsahů.
Překryv anotací nesmí sám způsobit duplicitní emisi bajtů. Konkrétní pravidla
rozdělení překrývajících se anotací do parts jsou ještě otevřená.

Skript smí parts přeskupovat. Framework nesmí obecně zakazovat pořadí jen proto,
že je neobvyklé nebo ho protistrana nemusí přijmout. Odpovídá za sestavení známých
reprezentací a jednoznačně určených závislostí, ne za záruku úspěchu aplikace.

Přepočet hlavičky vychází z následujících **relevantních** parts. Relevantnost
musí zohledňovat konkrétní zprávu, směr a případný protokolový stream; nesmí
znamenat prostě všechny bajty za hlavičkou. Nejednoznačnou závislost commit
odmítne, místo aby ji odhadoval.

## Typy částí

Typ určuje, co part reprezentuje, ne protokol celého spojení. Například HTTP
obsah může zahrnovat MIME části. Samostatný `Protocol` přepínač není součástí
tohoto modelu.

```python
for part in api.message.parts:
    if part.is_a(PartType.Http1.Part):
        # Rodina HTTP/1 částí, například Header nebo Body.
        ...
    elif part.is_a(PartType.Mime.Part):
        ...
    elif part.type == PartType.Opaque:
        data = part.get_bytes()

return api.message.commit()
```

- `part.type == ...` porovnává přesný typ.
- `part.is_a(...)` testuje příslušnost do rodiny typů.
- `PartType.Opaque` znamená obsah bez protokolové interpretace. Má stejné základní
  operace čtení, zápisu, commit a hold jako ostatní části.
- Protokolové API musí mít oporu v anotacích nebo explicitně vytvořeném typovaném
  partu. Text připomínající HTTP uvnitř Opaque části se nesmí sám stát HTTP API.

Příklady ukazují cílové API, nikoli seznam již dostupných implementací typů.

## Lazy reprezentace a původní bajty

Parts představují významový obsah. HTTP body může být zpřístupněné jako cleartext,
i když původní wire data byla gzipovaná.

`part.get_bytes()` podle potřeby vytvoří slice, kopii nebo dekódovanou reprezentaci.
Pouhá existence, iterace nebo podržení partu nesmí vyžadovat materializaci jeho
obsahu. Pokud je vhodná reprezentace už dostupná, může se znovu použít.

Čtení nesmí označit part jako změněný. Explicitní `part.set_bytes(data)` vytváří
změnu. Nezměněný part musí zachovat původní wire bajty; nesmí se zbytečně znovu
komprimovat ani serializovat. Stejný cleartext nemusí vytvořit identický gzip.

U Opaque části je převod reprezentace na wire obsah identita. Typované části
zajišťují odpovídající serializaci nebo kódování, pokud je podporované.

Velikost reprezentace, původní wire velikost a výsledná wire velikost jsou různé
veličiny a API je nesmí skrývat pod jedním nejasným `size()`. Encoding musí být
zjistitelný přímo, ne odhadem z rozdílu velikostí. Přesné názvy těchto atributů
zůstávají otevřené.

## Dvě úrovně commitu

`part.commit()` validuje změněnou reprezentaci a připraví její wire podobu.
Například serializuje hlavičky nebo znovu zkomprimuje upravené body.
Neodesílá data protistraně. U nezměněného partu jde o levný no-op.

`api.message.commit()` provede průchod všemi částmi určenými k výstupu a jejich
commit, následovaný společným sestavením. Dopočítá známé závislosti, například
Content-Length, rámování a výstupní offsety. Explicitní volání `part.commit()`
není povinné; slouží k včasné validaci nebo získání výsledné wire velikosti.
Podržené části nejsou výstup a samotný hold jejich commit nevynucuje.

```python
for part in api.message.parts:
    if part.type == PartType.Http1.Header:
        part.http1.set_header("X-Test", "another way")
    elif part.type == PartType.Http1.Body:
        api.print(part.get_bytes().hex())
        part.set_bytes(b"\r\n\r\n\r\n")

return api.message.commit()
```

Commit nesmí během sestavování publikovat dílčí změny. Neúspěšné sestavení vyvolá
chytatelnou `CommitException`, zachová původní vstup a ponechá drafty opravitelné.
Úspěšný lokální commit nezaručuje úspěch celkového commitu. Již odeslané bajty
z minulého callbacku nelze zpětně opravit.

Výsledný obsah se předává existujícím mechanismem návratu ze skriptu.
Payloadová transakce sama o sobě neslibuje rollback externích operací,
sdíleného úložiště ani ostatních vedlejších účinků skriptu.

## Úplnost části a obsahu

```python
part.complete
part.content.complete
```

`part.complete` vyjadřuje úplnost konkrétní části, například H2 DATA rámce.
`part.content.complete` vyjadřuje úplnost příslušného celého obsahu, například
HTTP body. Kompletní DATA rámec tedy nemusí znamenat kompletní content.

Obě vlastnosti rozlišují `True`, `False` a `None`: úplné, prokazatelně neúplné,
a z dostupných informací neurčitelné. Zjištění úplnosti samo nesmí vyžadovat
zbytečné materializování decoded obsahu.

Úplný content vyžaduje známý konec i přítomnost všech potřebných částí.
Samotný END_STREAM ani úspěšný inflate to nezaručují. `content` je kontext
souvisejících částí, ne automaticky další kopie bajtů nebo samostatný stream view.

Framework nečeká magicky na budoucí callbacky. Skript, který potřebuje celý
obsah, musí příslušné části podržet. Pokud bude měnit délku body, musí zachovat
i možnost upravit související hlavičku; emitovanou hlavičku hold body nevrátí.

## Streams bez automatických pohledů

`part.stream_id` je vždy integer. U částí s protokolovým stream ID obsahuje
skutečné ID; jinak má hodnotu **1**, včetně Opaque částí. Skutečná nula zůstává
nulou, například u connection-level H2 rámců.

```python
for part in api.message.parts:
    if part.stream_id == 1:
        # Záměrně zahrnuje skutečný stream 1 i části s výchozí hodnotou.
        ...
```

Výběr a seskupování provádí skript. API zatím nevytváří automatické per-stream
views ani pořadí podle streamů. Interní vazby nesmějí vycházet pouze z veřejného
`stream_id`: výchozí 1 nedokazuje příslušnost Opaque části k H2 streamu 1.

## Hold uchovává celé Parts

Free-form `hold(N)` nad bajty není cílový model. Zadržujeme celé parts se zachováním
jejich významu, nikoli bajty určené k novému rozpoznávání.

```python
api.message.parts.hold_from(part)
```

Tato operace zadrží označenou část i všechny následující části v aktuálním pořadí.
Předcházející prefix může být sestaven a odeslán. Skript může před operací seznam
přeskupit; neexistuje obecný zákaz, že původně pozdější part nesmí předběhnout
podržený part.

Hold buffer zachovává typ, stream ID, úplnost, anotace, interní vazby, původní
wire obsah, lazy reprezentaci, rozpracované změny a případný výsledek lokálního
commitu. Hold sám nevynucuje decode ani commit. Podržené části se z aktuálního
výstupu zkonzumují a protistraně nesmějí odejít.

Další běh dostane podržené parts před novými se zachovaným pořadím. Backend musí
uchovat jejich významový stav mezi zanikajícími Python workery; nesmí se spoléhat
na přežití Python objektů. Životnost transportně podrženého obsahu nelze zaměnit
za životnost uživatelského `api.state`.

Podržení musí být izolované minimálně podle deploymentu, spojení a směru;
endpoint instancing nesmí smíchat data různých spojení. Přesné transakční chování
mezi více skripty a při změně deploymentu je otevřený implementační kontrakt.

## Vlastní typované Parts

Skript může do seznamu vložit nově vytvořený part, například cílově:

```python
ping = api.http2.Ping(opaque_data=b"12345678")
api.message.parts.append(ping)
```

Nový part nemá původní wire rozsahy, ale sdílí stejný commit kontrakt. Typovaná
serializace kontroluje požadavky konkrétního typu; příklad PING konstruktoru
není příslib již implementované podpory. Interakce vložených řídicích rámců
s protistranou, například zpracování ACK, musí mít výslovně určené chování.

## Stavové dekódování a anotace

Živý stavový engine zpracovává každý nový příchozí bajt právě jednou. Složený
vstup skriptu obsahující podržené parts se nesmí znovu přehrát do živého HPACK
nebo dekompresního stavu.

```text
nový vstup → stavový enrichment → nové parts
                                    + podržené parts
                                    ↓
                               pracovní zpráva
                                    ↓
                         editace / hold / commit
```

Přesuny a sestavení přepočítávají souřadnice a vazby anotací. Framework nemusí
opravovat jejich původní věcnou správnost ani překryvy. Musí ale zachovat původ
odvozených reprezentací; enrichment přes více callbacků není obyčejný slice.

Stav dekodéru příchozího streamu a stav protistrany po změnách výstupu nejsou
totéž. Zvláště zápisy do HPACK nelze prohlásit za bezpečné pouze proto, že
umíme serializovat jednu hlavičku.

## Viditelnost změn v GUI

Publikace do GUI musí jednoznačně sdělit alespoň to, že se obsah změnil nebo
byl podržen. Původní payload a jeho anotace nesmějí být vydávány za skutečně
odeslaný změněný výstup.

Metadata zpracování mají odlišit příchozí, změněný, podržený, uvolněný a odeslaný
obsah a identifikovat původní callbacky a zasahující skript. Přesné názvy polí
a rozsah uchovávaného výstupního obsahu nejsou zatím stanovené. Pouhý příznak
změny neopravňuje GUI zobrazovat rekonstruovaný výstup jako skutečně zachycený.

## Otevřená rozhodnutí před implementací holdu

- Atomická návaznost hold bufferů a výstupu v řetězci více skriptů.
- Chyba, timeout nebo nedostupný worker po předchozím úspěšném holdu. Běžné
  „pusť jen aktuální originál“ není dostatečné: ztratilo by starší zadržené části.
- Ukončení spojení, disable, redeploy, změna filtru a restart backendu.
- Limity paměti, délky čekání a politika při jejich překročení.
- Serializace a verzování uchovávaných parts, včetně neúplných reprezentací.
- Způsob doplnění neúplného partu nebo content kontextu dalšími callbacky bez
  dvojího průchodu živým dekodérem.
- Přesná pravidla překryvů anotací, rozdělení parts a vazeb mezi nimi.
- Chování `return None`, chyb a ad-hoc preview při práci s hold bufferem.

Tyto situace musí být vyřešené a otestované před použitím holdu na živém provozu.
Nesmějí implicitně vést ke ztrátě, duplicitní emisi nebo úniku zadrženého obsahu.

## Vztah k současné implementaci

K datu této verze existuje první write API přes `api.message.snapshot()` a
monolitický `draft.http1`, s privátním commitem a přepočtem Content-Length pro
omezenou množinu kompletních HTTP/1 zpráv. Parts, významový hold buffer a uvedené
typované konstruktory představují cílový návrh, nikoli hotové runtime API.

Současné rozpoznání HTTP/1 snapshotu přímo z bajtů musí být při přechodu na Parts
nahrazeno interpretací opřenou o anotace. Monolitický snapshot není vzor pro
další růst veřejného API; jeho validační a serializační logika může sloužit
jako stavební dílek jednotlivých parts a jejich společného commitu.

## Ověřovací kritéria

Testy implementace musí pokrývat zachování původních wire bajtů po pouhém čtení,
lazy materializaci, Opaque mezery, typovou hierarchii a výchozí stream ID 1.
Dále musí odlišovat úplnost rámce od contentu, ověřovat atomický commit a
opakovaný pokus po CommitException a prokázat zachování významu parts přes hold.

Transportní testy musí ověřit, že podržený obsah neodejde předčasně, po uvolnění
neodejde dvakrát, nesmíchá se mezi spojeními a znovu nevstoupí do živého dekodéru.
GUI testy musí odlišovat původní vstup od změněného nebo podrženého výstupu.
