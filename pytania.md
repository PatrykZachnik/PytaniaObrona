## Podstawowe typy i struktury danych w językach programowania.

1.  Programowanie skryptowe i obiektowe to dwa różne podejścia do tworzenia oprogramowania, z różnicami w filozofii projektowej, strukturze kodu i sposobie rozwiązywania problemów. Poniżej znajdziesz porównanie obu podejść:
    - Programowanie skryptowe:
        - Charakterystyka: Programowanie skryptowe polega na tworzeniu skryptów, czyli zestawów instrukcji, które wykonują konkretne zadania. Skrypty są zwykle interpretowane lub kompilowane „na żywo” i nie wymagają zazwyczaj budowania całościowego programu.
        - Dynamiczne typowanie: W skryptach często stosuje się dynamiczne typowanie, co oznacza, że zmienne nie są związane z konkretnymi typami danych.
        - Prostota: Skrypty często są proste w nauce i używaniu, ponieważ mogą zawierać tylko te elementy, które są niezbędne do wykonania określonego zadania.
        - Języki: Przykłady języków skryptowych to Python, Ruby, JavaScript, PHP.
    - Programowanie obiektowe</b>:
        - Charakterystyka: Programowanie obiektowe (POO) opiera się na tworzeniu klas i obiektów, które zawierają dane w postaci pól (często nazywanych właściwościami lub atrybutami) oraz metody, które operują na tych danych.
        - Abstrakcja i hermetyzacja: W POO dane i metody są zwykle hermetyzowane wewnątrz obiektów, co oznacza, że są one dostępne tylko dla konkretnego obiektu lub klasy. To zapewnia abstrakcję danych.
        - Dziedziczenie i polimorfizm: POO wykorzystuje dziedziczenie, co oznacza, że nowe klasy mogą być tworzone na podstawie istniejących klas, oraz polimorfizm, co pozwala na przeciążanie metod.
        - Języki: Języki obiektowe to m.in. Java, C++, C#, Python (umożliwiający zarówno programowanie obiektowe, jak i skryptowe), Ruby.
	Podsumowując, programowanie skryptowe jest często stosowane do szybkiego prototypowania, ma 	mniejsze wymagania dotyczące struktury i składni, podczas gdy programowanie obiektowe stawia na 	organizację kodu wokół obiektów, co ułatwia zarządzanie większymi projektami i zapewnia większą 	modularność i skalowalność. Oba podejścia mają swoje zastosowania w zależności od potrzeb 	projektu.

## Proszę porównać koncepcje programowania skryptowego i obiektowego.

2.  Typy danych i struktury danych są fundamentalnymi elementami w językach programowania, które umożliwiają manipulację i organizację danych w programach. Poniżej przedstawiam podstawowe typy danych i struktury danych, które występują w większości języków programowania:

    - Typy danych podstawowe:
    
        Integer (liczba całkowita): Reprezentuje liczby całkowite, np. 1, 100, -5.
        Float (liczba zmiennoprzecinkowa): Reprezentuje liczby zmiennoprzecinkowe, np. 3.14, 2.5, -0.001.
        String (łańcuch znaków): Reprezentuje sekwencje znaków, np. "hello", "world", "abc123".
        Boolean (wartość logiczna): Reprezentuje wartość logiczną True (prawda) lub False (fałsz).
        Char (znak): Reprezentuje pojedynczy znak, np. 'a', 'X', '$'.

    - Typy danych złożone:

        List (lista): Kolekcja elementów, które mogą być różnych typów i przechowywane są w określonej kolejności.
        Tuple (krotka): Podobna do listy, ale elementy są niemodyfikowalne (immutable), a jej rozmiar jest stały.
        Dictionary (słownik): Skojarzenie kluczy z wartościami, umożliwiające szybkie wyszukiwanie po kluczu.
        Set (zbiór): Kolekcja unikalnych elementów, w której nie ma duplikatów.

    - Struktury danych:

        Tablica (array): Uporządkowany zestaw elementów tego samego typu.
        Stos (stack): Struktura danych LIFO (Last-In-First-Out), w której ostatni element dodany jest pierwszy do usunięcia.
        Kolejka (queue): Struktura danych FIFO (First-In-First-Out), w której pierwszy element dodany jest pierwszy do usunięcia.
        Drzewo (tree): Hierarchiczna struktura danych, w której każdy element może mieć kilka potomków.
        Graf (graph): Zbiór wierzchołków połączonych krawędziami, które mogą mieć różne relacje.

Te typy danych i struktury danych są wykorzystywane do przechowywania, organizowania i manipulowania danymi w programach komputerowych. Każdy język programowania może mieć swoje własne implementacje tych struktur, choć podstawowe zasady działania są zazwyczaj podobne.

## Sposoby przechowywania i kodowania informacji w systemie komputerowym.
### Co autor miał na myśli?

3. Przechowywanie i kodowanie informacji w systemie komputerowym odbywa się na różne sposoby, w zależności od rodzaju danych i wymagań aplikacji. Poniżej przedstawiam podstawowe sposoby przechowywania i kodowania informacji:

    - <b>Binarny system liczbowy:</b>

        W systemie komputerowym informacje są przechowywane i przetwarzane za pomocą systemu liczbowego o podstawie 2, czyli systemu binarnego.
        W tym systemie informacje są reprezentowane za pomocą dwóch wartości: 0 i 1.
        Każda cyfra binarna to bit (binary digit), a grupa ośmiu bitów to jeden bajt (byte).

     - <b>Tekst:</b>

        Tekst jest przechowywany w systemie komputerowym jako sekwencje znaków.
        Tekst może być kodowany za pomocą różnych zestawów znaków, takich jak ASCII (American Standard Code for Information Interchange), Unicode, UTF-8 (Unicode Transformation Format).
        ASCII jest starszym standardem kodowania, który używa 7 bitów (128 znaków), natomiast Unicode i UTF-8 obsługują znacznie większy zakres znaków, co pozwala na obsługę wielu języków i symboli.

     - <b>Grafika:</b>

        Obrazy i grafika są przechowywane w postaci pikseli, które są małymi jednostkami, z których składa się obraz.
        Obrazy mogą być kodowane w różnych formatach, takich jak JPEG, PNG, GIF, BMP, które różnią się algorytmami kompresji i cechami związanymi z jakością i rozmiarem pliku.

     -  <b>Dźwięk:</b>

        Dźwięk jest przechowywany w postaci próbek dźwięku, które reprezentują wartości amplitudy dźwięku w określonych interwałach czasowych.
        Dźwięk może być kodowany w różnych formatach, takich jak MP3, WAV, AAC, które różnią się algorytmami kompresji i cechami jakości dźwięku.

    - <b>Wideo:</b>

        Wideo jest przechowywane jako sekwencje klatek (frames), gdzie każda klatka jest obrazem.
        Wideo może być kodowane w różnych formatach, takich jak MPEG, AVI, MP4, które różnią się algorytmami kompresji i cechami jakości wideo.

     - <b>Dane strukturalne:</b>

        Dane strukturalne, takie jak bazy danych, pliki XML, JSON, są przechowywane w określonych strukturach, które umożliwiają organizację i manipulację danymi zgodnie z ich formatem i relacjami.

Przechowywanie i kodowanie informacji w systemie komputerowym musi być zgodne z wymaganiami aplikacji oraz zapewnić niezawodność, integralność i efektywność w operacjach przetwarzania danych. Wybór odpowiedniego sposobu przechowywania i kodowania danych jest kluczowy dla efektywnego działania systemu komputerowego.

## Główne zadania i cechy systemu operacyjnego. Opisać na przykładzie wybranego środowiska.

4. System operacyjny Linux, znany także jako dystrybucje Linuxa (np. Ubuntu, Fedora, Debian), posiada swoje własne unikalne zadania i cechy, które są charakterystyczne dla tego otwartoźródłowego systemu. Poniżej przedstawiam główne zadania i cechy systemu operacyjnego Linux na przykładzie popularnej dystrybucji Ubuntu:
Główne zadania systemu operacyjnego Linux:

    - Zarządzanie zasobami:

        Linux zarządza zasobami sprzętowymi, takimi jak procesor, pamięć RAM, dyski twarde oraz urządzenia wejścia/wyjścia.
        Zapewnia efektywne wykorzystanie zasobów poprzez mechanizmy harmonogramowania procesów oraz alokacji pamięci.

    - Obsługa procesów:

        System Linux zarządza procesami, tj. uruchamia, wstrzymuje, wznawia oraz zamyka procesy.
        Zapewnia izolację procesów oraz mechanizmy komunikacji międzyprocesowej.

    - Zarządzanie pamięcią:

        Linux zarządza fizyczną i wirtualną pamięcią komputera.
        Oferuje mechanizmy alokacji pamięci dla procesów oraz obsługę pamięci podręcznej.

    - Zarządzanie plikami:

        System Linux obsługuje operacje na plikach i katalogach, takie jak tworzenie, czytanie, zapisywanie, usuwanie oraz zmiana uprawnień dostępu.
        Zapewnia mechanizmy kontroli dostępu do plików oraz obsługę systemu plików.

    - Interakcja z użytkownikiem:

        Linux oferuje różne interfejsy użytkownika, w tym interfejs tekstowy (konsola) oraz graficzny (środowiska graficzne, np. GNOME, KDE).
        Umożliwia konfigurację systemu, zarządzanie użytkownikami oraz instalację i zarządzanie aplikacjami.

Główne cechy systemu operacyjnego Linux:

-   Otwartoźródłowość:

    Linux jest systemem otwartoźródłowym, co oznacza, że jego kod źródłowy jest dostępny publicznie, co pozwala na modyfikację i dostosowanie systemu do indywidualnych potrzeb.

   - Wsparcie społeczności:
        Linux posiada duże wsparcie społeczności użytkowników i deweloperów, którzy aktywnie rozwijają, udoskonalają i udzielają pomocy w użytkowaniu systemu.

   -  Stabilność i niezawodność:
        Linux jest znany ze swojej stabilności i niezawodności, co czyni go popularnym wyborem do serwerów oraz urządzeń wbudowanych.

   - Bezpieczeństwo:
        Linux zapewnia wysoki poziom bezpieczeństwa dzięki mechanizmom kontroli dostępu, ochronie pamięci oraz szybkim reakcjom na znane zagrożenia.

   - Wsparcie dla różnych architektur:
        Linux działa na wielu architekturach sprzętowych, takich jak x86, ARM, PowerPC, co sprawia, że jest elastyczny i wszechstronny.
  
   - Skalowalność:
        Linux jest skalowalny i może być dostosowany do różnych zastosowań, od urządzeń wbudowanych i komputerów osobistych po duże klastry serwerów.

System operacyjny Linux, ze względu na swoje cechy i elastyczność, jest szeroko stosowany w różnych dziedzinach, od serwerów internetowych po komputery osobiste i urządzenia wbudowane. Jego popularność stale rośnie dzięki zaletom otwartoźródłowości, stabilności i bezpieczeństwa.

##

5. Licencjonowanie oprogramowania odnosi się do zasad i warunków, na jakich oprogramowanie może być używane, dystrybuowane lub modyfikowane. Istnieje wiele różnych metod licencjonowania, a ich wybór może mieć istotne konsekwencje dla użytkowników i twórców oprogramowania. Poniżej przedstawiam kilka przykładów metod licencjonowania oprogramowania:

    - Licencja typu public domain:

        Oprogramowanie udostępniane jest bez ograniczeń, co oznacza, że użytkownicy mogą korzystać, modyfikować i rozpowszechniać je bez konieczności przestrzegania jakichkolwiek ograniczeń prawnych.
        Przykład: biblioteki standardowe języka Python.

    - Licencja typu MIT:

        Jest to jedna z najbardziej liberalnych licencji. Pozwala na swobodne kopiowanie, modyfikowanie, publikowanie i sprzedaż oprogramowania, pod warunkiem, że oryginalne powiadomienie o prawach autorskich pozostaje nienaruszone.
        Przykład: framework webowy Flask dla języka Python.

    - Licencja typu GPL (General Public License):

        GPL narzuca pewne zobowiązania dla osób, które chcą korzystać z oprogramowania opartego na tej licencji. Wymaga, aby wszelkie zmodyfikowane wersje oprogramowania również były udostępniane na zasadach GPL.
        Przykład: system operacyjny Linux.
    
    - Licencja komercyjna (proprietary):

        Oprogramowanie jest objęte prawami autorskimi i użytkownicy muszą zapłacić za jego używanie lub licencję.
        Przykład: Microsoft Office, Adobe Photoshop.

    - Licencja trial (wersja próbna):

        Jest to rodzaj licencji, który pozwala użytkownikom na korzystanie z oprogramowania przez określony okres czasu lub z ograniczeniami funkcjonalnymi. Po upływie okresu próbnego użytkownik musi zakupić pełną licencję.
        Przykład: Wiele programów komercyjnych oferuje wersje próbne, takie jak Adobe Photoshop czy Microsoft Office.

## Podstawowe koncepcje działania relacyjnych baz danych.

6. Relacyjne bazy danych (RDBMS) opierają się na kilku podstawowych koncepcjach, które są kluczowe dla ich działania. Oto kilka z tych koncepcji:

    - Tabela:
        Tabela jest podstawowym elementem relacyjnej bazy danych. Reprezentuje ona zestaw danych zorganizowanych w kolumny (atrybuty) i wiersze (rekordy).
        Każda kolumna tabeli odpowiada określonemu typowi danych, np. liczba całkowita, tekst, data, itp.

    - Klucz główny (Primary Key):

        Klucz główny to unikalny identyfikator dla każdego rekordu w tabeli. Zapewnia on jednoznaczną identyfikację rekordów w tabeli.
        Klucz główny może składać się z jednej lub kilku kolumn tabeli.

    - Relacja:

        Relacja to połączenie między tabelami oparte na wspólnych wartościach w kolumnach.
        Relacje są tworzone za pomocą kluczy obcych, które odnoszą się do kluczy głównych innych tabel.

    - Klucz obcy (Foreign Key):

        Klucz obcy to kolumna w tabeli, która zawiera wartości, które odnoszą się do klucza głównego innej tabeli.
        Klucz obcy tworzy relacje między tabelami, umożliwiając zdefiniowanie powiązań między nimi.

    - Normalizacja:

        Normalizacja to proces organizacji danych w bazie danych w celu uniknięcia nadmiarowości informacji oraz zapewnienia spójności i integralności danych.
        Normalizacja polega na podziale danych na mniejsze, logicznie powiązane struktury, co ułatwia zarządzanie danymi i zapobiega błędom.

    - Transakcje:

        Transakcja to sekwencja operacji wykonywanych na bazie danych, która musi być wykonana w całości lub w ogóle.
        Transakcje są atomowe, spójne, izolowane i trwałe (ACID), co oznacza, że są bezpieczne i niezawodne nawet w przypadku wystąpienia błędów lub awarii.

    - Język zapytań SQL:

        SQL (Structured Query Language) jest standardowym językiem zapytań używanym do zarządzania relacyjnymi bazami danych.
        Umożliwia wykonywanie różnych operacji na danych, takich jak dodawanie, usuwanie, aktualizacja, sortowanie i filtrowanie.

    - Indeksy:

        Indeksy są strukturami danych używanymi do przyspieszenia wyszukiwania i dostępu do danych w bazie danych.
        Tworzenie indeksów na kolumnach często używanych w zapytaniach pozwala na szybsze przetwarzanie i optymalizację zapytań.

Te podstawowe koncepcje działania relacyjnych baz danych pomagają w zrozumieniu struktury i funkcji takich baz danych oraz w efektywnym ich wykorzystaniu do przechowywania, zarządzania i przetwarzania danych.

## Proszę wymienić podstawowe grupy instrukcji języka SQL i scharakteryzować każdą z grup.

7. Oto podstawowe grupy instrukcji języka SQL:

    - Instrukcje DDL (Data Definition Language):
        Instrukcje DDL służą do definiowania struktury bazy danych, takich jak tworzenie, modyfikacja i usuwanie obiektów bazy danych.
        Najważniejsze instrukcje DDL to:

           - CREATE: Służy do tworzenia obiektów bazy danych, takich jak tabele, indeksy, widoki.
           - ALTER: Umożliwia zmianę struktury obiektów bazy danych, np. dodawanie, usuwanie lub zmiana kolumn tabeli.
           - DROP: Służy do usuwania obiektów bazy danych, np. tabel, indeksów, widoków.

    - Instrukcje DML (Data Manipulation Language):
        Instrukcje DML służą do manipulacji danymi w bazie danych, takimi jak dodawanie, usuwanie, aktualizacja oraz pobieranie danych.
        Najważniejsze instrukcje DML to:

           - INSERT: Służy do dodawania nowych rekordów do tabeli.
           - SELECT: Umożliwia pobieranie danych z bazy danych za pomocą zapytań.
           - UPDATE: Pozwala na aktualizację istniejących rekordów w tabeli.
           - DELETE: Służy do usuwania rekordów z tabeli.

   - Instrukcje DCL (Data Control Language):
        Instrukcje DCL kontrolują dostęp do danych w bazie danych i zarządzają uprawnieniami użytkowników.
        Najważniejsze instrukcje DCL to:

           - GRANT: Przyznaje uprawnienia użytkownikom do wykonywania określonych operacji na obiektach bazy danych.
           - REVOKE: Odwołuje lub usuwa uprawnienia użytkowników do dostępu do obiektów bazy danych.

   - Instrukcje TCL (Transaction Control Language):
        Instrukcje TCL kontrolują transakcje w bazie danych, czyli operacje wykonywane w określonej sekwencji i zapewniające ich atomowość, spójność, izolację i trwałość (ACID).
        Najważniejsze instrukcje TCL to:

           -  COMMIT: Potwierdza transakcję, zatwierdzając zmiany w bazie danych.
           -  ROLLBACK: Anuluje transakcję i cofa wszystkie zmiany wprowadzone w jej trakcie.
           - SAVEPOINT: Ustawia punkt kontrolny w trakcie transakcji, co umożliwia późniejsze wycofanie się do tego punktu w przypadku potrzeby.

Instrukcje SQL z tych różnych grup pozwalają na kompleksowe zarządzanie bazami danych, od ich struktury, poprzez manipulację danymi, kontrolę dostępu, po zarządzanie transakcjami. Dzięki nim możliwe jest skuteczne tworzenie, modyfikowanie i obsługa baz danych zgodnie z wymaganiami aplikacji i użytkowników.

## Problemy związane ze współbieżnym wykonaniem operacji na bazie danych. Ocena zjawisk niepożądanych.

8.Współbieżne wykonanie operacji na bazie danych może prowadzić do różnych problemów, zwłaszcza gdy wiele operacji jest wykonywanych jednocześnie przez wielu użytkowników. Oto kilka potencjalnych problemów związanych ze współbieżnym wykonaniem operacji na bazie danych, oraz ocena zjawisk niepożądanych:

    - Zatkanie się (Deadlock):
        Deadlock występuje, gdy dwa lub więcej procesów oczekuje na zasoby, które są zablokowane przez inne procesy. W efekcie żaden z procesów nie może kontynuować działania, co prowadzi do zatrzymania działania aplikacji.
        Ocena: Deadlocki są niepożądane, ponieważ prowadzą do zablokowania zasobów i uniemożliwiają dalsze działanie aplikacji. Mogą być trudne do wykrycia i rozwiązania.

    - Konflikty dostępu: 
        Gdy dwie lub więcej operacji próbuje jednocześnie modyfikować te same dane, może dojść do konfliktu. Przykładem może być sytuacja, gdy dwie osoby próbują jednocześnie wypłacić pieniądze z tego samego konta bankowego1.

    - Niespójność danych:
         Jeśli operacje są wykonywane w sposób niekontrolowany, może dojść do niespójności danych. Na przykład, jeśli operacja przeniesienia pieniędzy z jednego konta na drugie jest przerywana po odjęciu kwoty z jednego konta, ale przed dodaniem jej do drugiego, dane stają się niespójne1.

    - Problemy z izolacją:
         Jeśli operacje nie są odpowiednio izolowane, efekty jednej operacji mogą być widoczne dla innej przed jej zakończeniem. To może prowadzić do nieprawidłowych wyników

Wszystkie te problemy mogą prowadzić do niestabilności, spadku wydajności i błędów w aplikacji. Dlatego ważne jest, aby projektować systemy bazodanowe z myślą o obsłudze współbieżnych operacji i stosować odpowiednie mechanizmy, takie jak blokady, transakcje izolacyjne oraz monitorowanie wydajności, aby minimalizować ryzyko wystąpienia tych problemów.

## Proszę opisać podstawowe topologie sieci komputerowych.

- Topologia magistrali (Bus): 

    Wszystkie urządzenia są podłączone do wspólnego medium transmisyjnego1. Jest to topologia prosta i tania, ale niewielka przepustowość i podatność na awarie mogą stanowić problem

    ![Alt text](https://th.bing.com/th/id/R.59a5cd1a502f004ce4eeb7100b14e16d?rik=FatFyB8YOZ2kAw&riu=http%3a%2f%2f1.bp.blogspot.com%2f-EMcJAmJoYXg%2fUFUf41vsluI%2fAAAAAAAAADc%2fAYb_BCp28oU%2fs400%2fmagistrala.jpeg&ehk=OSXqipdC49rKWkz8PhajhLKzIrZysASnskyWKH5hInw%3d&risl=&pid=ImgRaw&r=0)

- Topologia liniowa: 

    Odmiana topologii magistrali, w której     każdy element sieci (oprócz granicznych) połączony jest dokładnie z dwoma sąsiadującymi elementami

    ![Alt text](https://upload.wikimedia.org/wikipedia/commons/4/4a/Liniowa.jpeg)

- Topologia pierścienia:

    Poszczególne elementy są połączone ze sobą w taki sposób jak w topologii liniowej, a dodatkowo połączone zostały elementy graniczne tworząc zamknięty pierścień

    ![alt text](https://upload.wikimedia.org/wikipedia/commons/b/b1/Pierscien.jpeg)

- Topologia gwiazdy:

    Elementy końcowe są podłączone do jednego punktu centralnego, koncentratora lub przełącznika

    ![alt text](https://upload.wikimedia.org/wikipedia/commons/a/a3/Gwiazda.jpeg)
- Topologia siatki: 

    Elementy łączą się bezpośrednio, dynamicznie i niehierarchicznie z jak największą liczbą innych elementów i współpracują ze sobą w celu efektywnego trasowania danych

    ![alt text](https://upload.wikimedia.org/wikipedia/commons/b/b6/Siatka.jpeg)

## Definicja i funkcje protokołu komunikacyjnego. Proszę dokonać przeglądu najczęściej używanych protokołów komunikacyjnych

Protokół komunikacyjny to zbiór ścisłych reguł oraz kroków postępowania, które są automatycznie wykonywane przez urządzenia komunikacyjne w celu nawiązania łączności i wymiany danych. W telekomunikacji, protokół komunikacyjny jest systemem regulacji, które umożliwiają dwóm lub więcej jednostkom systemu komunikacji do przesyłania informacji różnego typu fizycznej jakości. Regulacje te (standardy) definiują składnię, semantykę, synchronizację komunikacji oraz możliwe metody naprawiania błędów. Protokoły te mogą zostać wdrożone za pomocą sprzętu, oprogramowania lub obu naraz.

Najczęściej używane protokoły komunikacyjne to:

1. **TCP/IP** (Transmission Control Protocol / Internet Protocol) - to zespół protokołów sieciowych używany w sieci Internet⁵.
2. **HTTP** (HyperText Transfer Protocol) - protokół przesyłania dokumentów hipertekstowych, najczęściej stosowany do przesyłania danych przez stronę internetową.
3. **FTP** (File Transfer Protocol) - protokół służący do przesyłania plików w sieciach TCP/IP.
4. **DNS** (Domain Name System) - protokół używany do tłumaczenia nazw domen na adresy IP.
5. **SSH** (Secure Shell) - protokół służący do zdalnego logowania do systemu.
6. **IMAP** (Internet Message Access Protocol) - protokół służący do zarządzania pocztą elektroniczną.
7. **SMTP** (Simple Mail Transfer Protocol) - protokół służący do przesyłania poczty elektronicznej.
8. **POP3** (Post Office Protocol version 3) - protokół służący do odbierania poczty elektronicznej.
9. **HTTPS** (HTTP Secure) - protokół służący do bezpiecznej komunikacji przez sieć.


## Proszę scharakteryzować architekturę klient-serwer oraz podać przykłady realizacji


Architektura klient-serwer to model komunikacji między systemami komputerowymi, w którym jeden system (klient) żąda zasobów lub usług od innego systemu (serwera). Klient jest odpowiedzialny za inicjowanie żądań, a serwer odpowiada na te żądania, dostarczając żądane zasoby lub usługi. Architektura klient-serwer jest powszechnie stosowana w systemach informatycznych, w tym w aplikacjach internetowych, bazach danych, serwerach plików i wielu innych.

Strona klienta jest stroną żądającą dostępu do danej usługi lub zasobu. Tryb pracy klienta jest aktywny, wysyła żądanie do serwera i oczekuje na odpowiedź od serwera.

Strona serwera jest stroną świadczącą usługę lub udostępniającą zasoby. Tryb pracy serwera jest pasywny, czeka na żądania od klientów, a w momencie otrzymania żądania, przetwarza je, a następnie wysyła odpowiedź

Przykłady realizacji architektury klient-serwer to:

    Serwer poczty elektronicznej
    Serwer WWW
    Serwer plików
    Serwer aplikacji
    Większość obecnie spotykanych systemów zarządzania bazą danych
    Gry online

## Najczęściej spotykane typy zagrożeń bezpieczeństwa sieciowego. Proszę podać metody zapobiegania.
Oto kilka najczęściej spotykanych typów zagrożeń bezpieczeństwa sieciowego oraz metody zapobiegania:

    Ataki hakerskie:
        Zagrożenia: Hakerzy mogą próbować nieautoryzowanego dostępu do systemów, kradzieży danych, sabotowania usług lub wykorzystywania systemów do własnych celów.
        Zapobieganie: Regularna aktualizacja oprogramowania, zastosowanie silnych haseł, konfiguracja zabezpieczeń sieciowych, wykorzystanie systemów detekcji i reakcji na incydenty (IDS/IPS), firewalli, VPN, autoryzacja wieloskładnikowa.

    Malware:
        Zagrożenia: Złośliwe oprogramowanie, takie jak wirusy, trojany, ransomware, mogą infekować systemy, kradnąc dane, szpiegując użytkowników, przeszkadzając w działaniu lub blokując dostęp do zasobów.
        Zapobieganie: Instalacja antywirusów i oprogramowania anty-malware, regularne skanowanie systemów, unikanie klikania w podejrzane linki i pobierania nieznanych plików, aktualizacja oprogramowania.

    Phishing:
        Zagrożenia: Atakujący podszywa się pod zaufane źródło (np. bank, firma) i próbuje uzyskać poufne informacje od użytkowników, takie jak hasła, numery kart kredytowych, czy dane osobowe.
        Zapobieganie: Edukacja użytkowników w zakresie rozpoznawania phishingu, ostrożność przy otwieraniu załączników i klikaniu w linki w e-mailach, stosowanie filtrów antyspamowych, używanie autoryzacji dwuetapowej.

    Ataki DDoS (Distributed Denial of Service):
        Zagrożenia: Atakujący wysyła ogromną ilość żądań do serwera lub sieci, powodując przeciążenie i uniemożliwiając normalne funkcjonowanie.
        Zapobieganie: Używanie firewalli, systemów IDS/IPS, ograniczanie dostępu do usług tylko dla zaufanych adresów IP, zastosowanie rozproszonych systemów CDN, regularne monitorowanie ruchu sieciowego.

    Wycieki danych:
        Zagrożenia: Nieautoryzowane ujawnienie poufnych danych, takich jak dane klientów, informacje finansowe lub tajemnice handlowe, może prowadzić do szkód finansowych, utraty reputacji i naruszenia przepisów prawnych.
        Zapobieganie: Zabezpieczenie danych za pomocą szyfrowania, ograniczenie dostępu do danych tylko dla uprawnionych użytkowników, regularne audyty bezpieczeństwa, stosowanie polityk bezpieczeństwa informacji.

    Ataki z wykorzystaniem słabych konfiguracji:
        Zagrożenia: Atakujący mogą wykorzystać słabe hasła, niewłaściwie skonfigurowane serwery, niezaktualizowane oprogramowanie do uzyskania dostępu do systemów lub danych.
        Zapobieganie: Regularna zmiana i stosowanie silnych haseł, aktualizacja oprogramowania i systemów operacyjnych, konfiguracja zabezpieczeń sieciowych, stała kontrola i analiza logów systemowych.

Ważne jest, aby stosować zróżnicowane metody i narzędzia zapobiegania, aby zminimalizować ryzyko wystąpienia zagrożeń bezpieczeństwa sieciowego. Regularne szkolenia pracowników w zakresie bezpieczeństwa cybernetycznego oraz monitorowanie i reagowanie na incydenty są również kluczowe dla skutecznej ochrony sieci.