# H2 translate: izolovaný proof of concept

> Navazující živé napojení je popsáno v [H2_TRANSLATE_LIVE.md](H2_TRANSLATE_LIVE.md).
> Tento dokument zachovává rozsah původního izolovaného experimentu.

**Experiment, ne veřejné produkční API.** `tools/h2_translate_poc.py` se nevkládá
do workeru ani schematu editoru. Přidává testovací závislost `python-hpack`;
nezávislým přijímacím dekodérem v testech je systémová knihovna nghttp2.

## Kontrakt experimentu

Jedna `TranslateConnection` odpovídá jednomu novému spojení od prvního HPACK
bloku, nikoli jednomu H2 streamu. Každý směr má vlastní input Decoder a output
Encoder. Vstupní tabulka vidí původní hlavičky; výstupní tabulka upravené.
Pozdější původní index se proto může na výstupu změnit na jiný index či literal.

Skript musí explicitně vrátit `api.message.translate()`. Samotný `commit()`,
`return None` nebo zahození výsledku je chyba. Po skončení callbacku nevzniká
žádný skrytý překlad. Další callback musí opět explicitně volat translate.
Pracovní tabulky se publikují až po úspěšném návratu skriptu; při chybě se
experimentální spojení označí jako nepoužitelné. To **není** implementace
produkčního dropu nebo strict handshake.

```python
def script(api):
    for part in api.message.parts:
        if part.headers is not None:
            part.headers.set_header(b"x-lab", b"changed")
    return api.message.translate()
```

V dalším callbacku není nutná další změna, ale překlad ano:

```python
def script(api):
    return api.message.translate()
```

## Záměrně úzký rozsah

- pouze flow instanciace, kompletní anotované bloky v aktuálním callbacku;
- HEADERS + CONTINUATION, logické byte hodnoty hlaviček, Huffman;
- output encoder vlastní indexování; `never` zachovává zákaz indexování,
  `without`/`incremental` z draftu zde neurčují výstupní HPACK strategii;
- DATA a kontrolní rámce zůstávají byte-for-byte; jejich editace je odmítnuta;
- explicitní indexy, raw HPACK, změny seznamu Parts, hold, Opaque, SETTINGS
  a osiřelé CONTINUATION jsou odmítnuty, ne potichu ignorovány;
- výchozí tabulky 4096 B, bez vyjednávání SETTINGS a ACK; nejde o kompletní H2
  state machine ani překlad flow-control oken. PUSH_PROMISE není samostatně
  certifikovaný testy tohoto POC.
- žádné zapnutí na již rozběhlém/neúplně zachyceném spojení. Volající harnessu
  musí dodat všechny callbacky v pořadí; nelze detekovat libovolně vynechaný vstup.

## Spuštění

```sh
python3 tests/inspection_translate_poc_test.py
cmake -S . -B build -DSPIDER_TEST_TRANSLATE_POC=ON
ctest --test-dir build --output-on-failure -R inspection_translate_poc
```

Testy ověřují změněný insert a původní index přes různé streamy/callbacky,
více bloků v jednom callbacku, L/R a nezávislá spojení, 200 deterministických
zpráv s eviction a opakovanými indexy, CONTINUATION a větší výstup,
nezměněné DATA/PING, povinné explicitní volání a atomické selhání.

Ověření 2026-10-25: rozšířený harness má 13 testů a prošel; celá sada s
experimentem prošla 23/23 (27,89 s). Negativní kontrola navíc ukazuje, že bez
překladu následný původní index vrátí nesprávnou hodnotu. Jde o in-process
experiment s důvěryhodným skriptem, nikoli sandboxovaný worker ani měření
produkční latence; kopírování stavů slouží zatím k jednoduché transakčnosti.

Před živým nasazením zbývá: potvrzení strict aktivace, produkční umístění a
životnost stavů, worker protokol, nastavení HPACK/SETTINGS, hold/reassembly,
omezení prostředků a chování při změně deploymentu. Současný rewrite není
experimentem nijak přepnutý ani změněný.
