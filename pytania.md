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

## Proszę wymienić obecnie stosowane metody szyfrowania danych
### Tutaj, jeżeli mialbym na czymś polegać to RSA/TLS/SSL/HTTPS/PGP
Oto kilka obecnie stosowanych metod szyfrowania danych:

    AES (Advanced Encryption Standard):
        Jest to symetryczny algorytm szyfrowania, który jest powszechnie stosowany do szyfrowania danych, takich jak wiadomości e-mail, dane transakcyjne i pliki. AES jest uważany za bardzo bezpieczny i wydajny.

    RSA (Rivest-Shamir-Adleman):
        Jest to asymetryczny algorytm szyfrowania, który wykorzystuje klucze publiczne i prywatne do szyfrowania i deszyfrowania danych. RSA jest szeroko stosowany do bezpiecznej wymiany kluczy oraz podpisywania i weryfikowania cyfrowych.

    DES (Data Encryption Standard) i 3DES (Triple DES):
        DES był standardem szyfrowania danych, ale obecnie jest uważany za przestarzały z uwagi na krótki klucz (56 bitów). 3DES jest ulepszoną wersją DES, która stosuje proces szyfrowania DES trzykrotnie. Choć 3DES jest nadal używany, zaleca się stopniową migrację na bardziej zaawansowane algorytmy.

    Blowfish i Twofish:
        Są to symetryczne algorytmy szyfrowania opracowane jako alternatywa dla DES. Są one stosowane do szyfrowania danych na różnych platformach i są uznawane za bezpieczne.

    ECC (Elliptic Curve Cryptography):
        Jest to rodzaj asymetrycznego algorytmu szyfrowania, który wykorzystuje krzywe eliptyczne do generowania kluczy kryptograficznych. ECC jest znany ze swojej wydajności i stosunkowo krótkich kluczy.

    TLS (Transport Layer Security) i SSL (Secure Sockets Layer):
        Są to protokoły szyfrowania stosowane do bezpiecznej transmisji danych przez sieci, takie jak internet. Wykorzystują one różne algorytmy szyfrowania, w tym AES i RSA, do zapewnienia poufności i integralności danych.

    PGP (Pretty Good Privacy) i GPG (GnuPG):
        Są to narzędzia do szyfrowania danych, zwłaszcza e-maili. Wykorzystują one kombinację symetrycznego i asymetrycznego szyfrowania do zapewnienia bezpieczeństwa w komunikacji e-mailowej.

    ChaCha20:
        Jest to szybki i bezpieczny algorytm szyfrowania stosowany w wielu aplikacjach, takich jak komunikatory internetowe i VPN.

Te metody szyfrowania danych stosowane są w różnych aplikacjach i systemach w celu zapewnienia poufności, integralności i bezpieczeństwa danych. Wybór odpowiedniego algorytmu szyfrowania zależy od konkretnych wymagań bezpieczeństwa oraz wydajności danego systemu.



## Proszę przedstawić zasadę działania komputera oraz funkcje zespołów bazowych.

Komputer to urządzenie elektroniczne, które przetwarza dane zgodnie z określonym programem. Działa na podstawie danych i instrukcji, które są wprowadzane do niego. Dane to konkretne informacje, takie jak pliki, zdjęcia i filmy. Instrukcje to polecenia, które mówią komputerowi, co ma robić. Komputer przetwarza te dane i instrukcje, aby wykonywać różne zadania.

Podstawowe zespoły bazowe komputera to:

1. **Procesor (CPU)**: Jest to rodzaj mikroprocesora, który wykonuje wszystkie obliczenia i operacje na danych. Procesor składa się z wielu milionów tranzystorów, które pracują na podstawie sygnałów elektrycznych.
2. **Pamięć RAM**: Przechowuje tymczasowe dane, które są aktualnie używane przez programy.
3. **Dysk twardy**: Magazynuje długoterminowe dane, takie jak pliki i aplikacje.
4. **Karta graficzna**: Odpowiedzialna za przetwarzanie grafiki i wyświetlanie obrazu na monitorze.
5. **Płyta główna**: Podstawowa płyta obwodów, na której montowane są pozostałe komponenty. Płyta główna jest odpowiedzialna za łączenie wszystkich innych podzespołów komputera, takich jak procesor, pamięć RAM, karta graficzna, dyski twarde i inne urządzenia.
6. **Zasilacz**: Dostarcza energię elektryczną do wszystkich komponentów komputera.
7. **System operacyjny**: Oprogramowanie, które zarządza sprzętem komputera i umożliwia użytkownikom korzystanie z różnych funkcji i programów.

Wszystkie te elementy są ze sobą połączone za pomocą przewodów, które przesyłają dane i zasilanie pomiędzy poszczególnymi komponentami

## Sposoby współpracy komputera z urządzeniami wejścia/wyjścia

Komputer współpracuje z urządzeniami wejścia/wyjścia (I/O) za pomocą różnych interfejsów i protokołów komunikacyjnych. Oto kilka sposobów, w jakie komputer może współpracować z urządzeniami wejścia/wyjścia:

1. **Porty komunikacyjne:**
   - Komputer może mieć różne porty komunikacyjne, takie jak porty USB, porty szeregowe (COM), porty równoległe (LPT), porty Ethernet czy porty audio. Urządzenia wejścia/wyjścia mogą być podłączane do tych portów za pomocą odpowiednich kabli i złączy.

2. **Sterowniki urządzeń:**
   - Komputer potrzebuje odpowiednich sterowników urządzeń, aby prawidłowo komunikować się z urządzeniami wejścia/wyjścia. Sterowniki te tłumaczą komunikaty i sygnały między komputerem a urządzeniem na zrozumiałe dla obu stron formy.

3. **Interfejsy bezprzewodowe:**
   - Komputer może współpracować z urządzeniami wejścia/wyjścia za pomocą interfejsów bezprzewodowych, takich jak Bluetooth, Wi-Fi czy NFC. Te interfejsy umożliwiają bezprzewodową transmisję danych między komputerem a urządzeniem.

4. **Protokoły komunikacyjne:**
   - Komputer może współpracować z urządzeniami wejścia/wyjścia za pomocą różnych protokołów komunikacyjnych, takich jak USB (Universal Serial Bus), HDMI (High-Definition Multimedia Interface), Ethernet, MIDI (Musical Instrument Digital Interface), czy też RS-232.

5. **Przetwarzanie sygnałów wejściowych:**
   - Komputer odbiera sygnały wejściowe od urządzeń wejścia, takich jak klawiatury, myszy, czy mikrofony, i przetwarza je na dane cyfrowe, które mogą być zrozumiałe dla programów i systemu operacyjnego.

6. **Wysyłanie sygnałów wyjściowych:**
   - Komputer przesyła sygnały wyjściowe do urządzeń wyjścia, takich jak monitory, drukarki, głośniki, czy też urządzenia zewnętrzne, aby wyświetlić informacje użytkownikowi lub wykonać określone czynności.

7. **Obsługa wielu urządzeń jednocześnie:**
   - Komputer może współpracować z wieloma urządzeniami wejścia/wyjścia jednocześnie, co umożliwia użytkownikom wykonywanie wielu zadań jednocześnie, takich jak pisanie na klawiaturze, przeglądanie internetu na monitorze i słuchanie muzyki na głośnikach, przy jednoczesnej obsłudze zewnętrznych urządzeń pamięci masowej czy drukowania.

## Właściwości grafiki rastrowej i wektorowej.

Grafika rastrowa (bitmapowa) i wektorowa to dwa główne rodzaje grafiki cyfrowej, z których każdy ma swoje charakterystyczne właściwości. Oto omówienie głównych właściwości każdego z tych rodzajów grafiki:
Grafika rastrowa (bitmapowa):

    Składanie pikseli: Grafika rastrowa składa się z pojedynczych pikseli, które tworzą obraz. Każdy piksel ma określoną wartość koloru i jest elementem siatki, której rozmiar definiuje rozdzielczość obrazu.

    Rozdzielczość: Obrazy rastrowe są definiowane przez ich rozdzielczość, wyrażaną w liczbie pikseli na jednostkę długości (np. pikseli na cal lub pikseli na centymetr). Większa rozdzielczość oznacza więcej pikseli na jednostkę długości i zwykle lepszą jakość obrazu.

    Skalowalność: Grafika rastrowa zazwyczaj ma ograniczoną skalowalność. Przy zmniejszaniu obrazu może występować utrata szczegółów, a przy powiększaniu obrazu może występować efekt rozmycia lub pikselizacji.

    Formaty plików: Popularne formaty plików grafiki rastrowej to JPEG, PNG, GIF, BMP, TIFF itp. Każdy z tych formatów ma swoje własne cechy, takie jak kompresja stratna lub bezstratna, obsługa przezroczystości, czy też obsługa animacji.

    Edycja obrazów: Programy do edycji grafiki rastrowej, takie jak Adobe Photoshop, GIMP, czy też Corel PaintShop Pro, umożliwiają edycję pikseli obrazu, w tym zmianę kolorów, dodawanie efektów, retuszowanie zdjęć itp.

    Popularne formaty plików rastrowych: jpg, jpeg, png, tif, bmp, gif, ico, tga, pdf (ten format jest akurat
    specyficzny, bo obsługuje również grafikę wektorową)

Grafika wektorowa:

    Opis kształtów: Grafika wektorowa opisuje obrazy za pomocą matematycznych równań i kształtów geometrycznych, takich jak linie, krzywe, okręgi, prostokąty itp.

    Skalowalność: Grafika wektorowa jest idealnie skalowalna, ponieważ opiera się na matematycznych równaniach, a nie na pikselach. Może być powiększana lub pomniejszana bez utraty jakości i szczegółów.

    Rozmiar plików: Pliki grafiki wektorowej są zazwyczaj mniejsze niż pliki grafiki rastrowej, ponieważ opisują kształty i linie za pomocą prostych równań matematycznych.

    Edycja obrazów: Grafika wektorowa jest łatwa do edycji, ponieważ kształty i linie mogą być łatwo manipulowane. Programy do edycji grafiki wektorowej, takie jak Adobe Illustrator, CorelDRAW, czy też Inkscape, umożliwiają tworzenie i edycję obrazów wektorowych.

    Zastosowania: Grafika wektorowa jest często stosowana w projektowaniu graficznym, projektowaniu stron internetowych, tworzeniu logo, ilustracji technicznych, czy też druku wielkoformatowym.

    Popularne formaty plików wektorowych: ai, eps, svg, cdr, pdf (ten format jest akurat specyficzny, bo
    obsługuje również grafikę rastrową)

Podsumowując, grafika rastrowa i wektorowa mają swoje własne zastosowania i charakterystyczne właściwości, dlatego wybór jednego rodzaju grafiki nad drugim zależy od konkretnego zastosowania i wymagań projektowych.


## Przykłady zastosowania grafiki komputerowej w aplikacjach użytkowych.
1. **Edycja grafiki i projektowanie:**
   - Programy do edycji grafiki, takie jak Adobe Photoshop, GIMP czy CorelDRAW, są wykorzystywane do tworzenia i edycji grafik, zdjęć, ilustracji, plakatów, broszur, ulotek, a także do projektowania logo, katalogów produktów czy materiałów reklamowych.

2. **Prezentacje multimedialne:**
   - Aplikacje do tworzenia prezentacji, takie jak Microsoft PowerPoint czy Keynote, pozwalają użytkownikom tworzyć dynamiczne prezentacje, wykorzystując grafikę, animacje, multimedia i efekty wizualne w celu przekazania informacji.

3. **Modelowanie 3D:**
   - W branży architektonicznej, inżynieryjnej, projektowania produktów, gier komputerowych i filmów animowanych wykorzystuje się oprogramowanie do modelowania 3D, takie jak Autodesk Maya, Blender czy Cinema 4D, do tworzenia realistycznych modeli trójwymiarowych.

4. **Projektowanie stron internetowych:**
   - Grafika komputerowa jest niezbędnym elementem przy projektowaniu interfejsów użytkownika i stron internetowych. Programy do projektowania stron, takie jak Adobe XD, Sketch czy Figma, umożliwiają projektowanie interaktywnych prototypów, wykorzystując grafikę, ikony, zdjęcia i inne elementy wizualne.

5. **Edycja wideo:**
   - Programy do edycji wideo, takie jak Adobe Premiere Pro, Final Cut Pro czy Davinci Resolve, wykorzystują grafikę komputerową do montażu filmów, dodawania efektów specjalnych, animacji, tytułów, przejść i innych elementów wideo.

6. **Oprogramowanie CAD (Computer-Aided Design):**
   - W branży inżynieryjnej, architektonicznej i projektowej wykorzystuje się oprogramowanie CAD, takie jak AutoCAD czy SolidWorks, do tworzenia precyzyjnych rysunków technicznych, modeli 3D i projektów konstrukcyjnych.

7. **Systemy informacji geograficznej (GIS):**
   - Grafika komputerowa jest wykorzystywana do tworzenia map, analiz przestrzennych, wizualizacji danych geograficznych i zarządzania danymi w systemach informacji geograficznej, takich jak ArcGIS czy QGIS.

8. **Grafika medyczna:**
   - W medycynie grafika komputerowa jest używana do tworzenia obrazów diagnostycznych, wizualizacji anatomicznych, symulacji medycznych, modelowania chorób i procedur chirurgicznych, a także do edukacji medycznej.

9. **Grafika edukacyjna:**
   - W edukacji grafika komputerowa jest wykorzystywana do tworzenia materiałów dydaktycznych, interaktywnych podręczników, animacji edukacyjnych, wirtualnych wycieczek, symulacji i gier edukacyjnych.

## Zasady projektowania diagramów przepływu danych oraz tworzenia modeli związków encji.

Wyjaśnienie zasad projektowania diagramów przepływu danych (DFD) oraz tworzenia modeli związków encji (ERM):
#### Tu trzeba to ogarnąć o co chodzi tak naprawdę...
### Zasady projektowania DFD:

1. **Określ hierarchię:** DFD może być ogólny lub szczegółowy. Zacznij od ogólnego widoku, a następnie przejdź do szczegółów.

2. **Rozdziel procesy od danych:** Oddziel procesy (czynności) od danych (informacji). Procesy to działania, które wykonuje system, a dane to informacje, które są przetwarzane.

3. **Zidentyfikuj procesy:** Dokładnie opisz procesy, jakie system wykonuje, aby wyjaśnić, co robią i jak działają.

4. **Pokazuj przepływ danych:** Strzałki na diagramie DFD pokazują, jakie dane są przetwarzane i jak przechodzą między procesami oraz innymi elementami systemu.

5. **Unikaj powtórzeń:** Unikaj powtarzania tych samych procesów w różnych miejscach. To może prowadzić do zbędnej złożoności.

### Zasady tworzenia modeli ERM:

1. **Identyfikuj encje:** Encje to obiekty lub pojęcia, które chcesz przechowywać w bazie danych. Na przykład, jeśli projektujesz bazę danych dla firmy, encje mogą obejmować klientów, produkty i zamówienia.

2. **Określ atrybuty:** Atrybuty to cechy lub właściwości encji. Dla klientów mogą to być imię, nazwisko, adres, itp.

3. **Określ związki:** Związki określają, jak encje są ze sobą powiązane. Na przykład, klient może mieć wiele zamówień, co oznacza związek "jeden do wielu" między klientem a zamówieniem.

4. **Normalizuj:** Sprawdź, czy baza danych jest dobrze zorganizowana, aby uniknąć powtórzeń i zapewnić spójność danych.

Te proste zasady pomagają w projektowaniu czytelnych i funkcjonalnych diagramów oraz modeli, co ułatwia zrozumienie i implementację systemów informatycznych.

### Proszę scharakteryzować strukturę języka UML.

Język UML (Unified Modeling Language) jest standardowym językiem notacji graficznej stosowanym do modelowania i dokumentowania systemów informatycznych oraz procesów biznesowych. Jego struktura obejmuje kilka głównych elementów, które pozwalają na reprezentację różnych aspektów systemu. Oto podstawowe składniki struktury języka UML:

1. **Diagramy:**
   - UML definiuje wiele rodzajów diagramów, z których każdy służy do modelowania określonych aspektów systemu. Najpopularniejsze diagramy UML to diagramy klas, diagramy przypadków użycia, diagramy sekwencji, diagramy aktywności, diagramy stanów, diagramy komponentów i diagramy wdrożeń.

2. **Elementy diagramów:**
   - Każdy diagram UML składa się z różnych elementów graficznych, takich jak klasy, interfejsy, przypadki użycia, aktorzy, obiekty, komponenty, artefakty, relacje, a także różne rodzaje linii i strzałek reprezentujących związki między elementami.

3. **Klasy i struktury:**
   - Klasy i struktury są podstawowymi elementami reprezentującymi obiekty w systemie. Klasy są reprezentowane w diagramach klas, a struktury w diagramach struktur.

4. **Relacje:**
   - Relacje między elementami UML określają powiązania i zależności między nimi. Na przykład, relacja dziedziczenia między klasami, relacja asocjacji między klasami, relacja agregacji czy kompozycji.

5. **Atrybuty i metody:**
   - Klasy w UML mogą posiadać atrybuty (cechy) i metody (zachowania). Atrybuty są reprezentowane za pomocą nazw i typów danych, a metody za pomocą nazw, parametrów i typów zwracanych.

6. **Przypadki użycia i aktorzy:**
   - Przypadki użycia reprezentują funkcjonalności systemu lub jego części z perspektywy użytkownika. Aktorzy to osoby, systemy zewnętrzne lub inne systemy korzystające z funkcji systemu.

7. **Diagramy interakcji:**
   - Diagramy interakcji, takie jak diagramy sekwencji i diagramy komunikacji, służą do modelowania interakcji między obiektami w systemie w określonym scenariuszu lub procesie.

8. **Diagramy stanów:**
   - Diagramy stanów opisują różne stany, przez które może przechodzić obiekt w systemie oraz przejścia między nimi w odpowiedzi na zdarzenia.

9. **Diagramy komponentów i wdrożeń:**
   - Diagramy komponentów reprezentują fizyczne lub logiczne komponenty systemu oraz ich zależności. Diagramy wdrożeń pokazują sposób, w jaki komponenty są rozmieszczone i wdrażane na fizycznych środowiskach.

Struktura języka UML jest elastyczna i umożliwia tworzenie różnorodnych diagramów, które mogą być używane w różnych fazach projektowania i rozwoju systemów informatycznych, począwszy od analizy i projektowania, aż po implementację i testowanie.

### Obiektowe projektowanie systemów informatycznych.

Obiektowe projektowanie systemów informatycznych (OOP - Object-Oriented Programming) to podejście do tworzenia oprogramowania, które opiera się na koncepcji obiektów i ich wzajemnych interakcji. OOP umożliwia bardziej zorganizowane, elastyczne i skalowalne tworzenie systemów poprzez grupowanie danych i funkcji w logiczne jednostki zwane obiektami. Oto kilka kluczowych aspektów obiektowego projektowania systemów informatycznych:

1. **Klasy i obiekty:**
   - Klasy są szablonami, które definiują właściwości i zachowania obiektów. Obiekty są instancjami klas, które posiadają konkretne wartości atrybutów i mogą wykonywać określone operacje.

2. **Enkapsulacja:**
   - Enkapsulacja polega na ukrywaniu wewnętrznych szczegółów implementacji obiektów i udostępnianiu jedynie interfejsu, który umożliwia manipulację nimi. To pozwala na tworzenie modułowego, łatwo rozszerzalnego i bezpiecznego kodu.

3. **Dziedziczenie:**
   - Dziedziczenie pozwala na tworzenie nowych klas na podstawie istniejących klas, przyjmując ich właściwości i metody oraz dodając nowe. Dzięki temu można unikać powtarzania kodu i budować hierarchie klas, które odzwierciedlają strukturę problemu.

4. **Polimorfizm:**
   - Polimorfizm pozwala na przypisywanie różnych znaczeń do tych samych operacji w różnych kontekstach. Dzięki temu można stosować te same metody do różnych typów danych, co prowadzi do elastyczności i ułatwia rozbudowę systemu.

5. **Związki i asocjacje:**
   - Obiekty mogą mieć relacje między sobą, które są reprezentowane za pomocą związków i asocjacji. To umożliwia modelowanie złożonych struktur danych i wzajemnych powiązań między obiektami.

6. **Wzorce projektowe:**
   - Wzorce projektowe to sprawdzone rozwiązania problemów, które mogą być stosowane w różnych kontekstach projektowych. Korzystanie z wzorców projektowych pomaga unikać błędów projektowych i zwiększa efektywność procesu projektowania.

7. **Testowanie i refaktoryzacja:**
   - Obiektowe projektowanie zachęca do tworzenia testów jednostkowych oraz do refaktoryzacji kodu, czyli jego restrukturyzacji w celu poprawy jego czytelności, wydajności i elastyczności.

8. **Iteracyjny proces projektowania:**
   - Proces projektowania systemów informatycznych zwykle przebiega iteracyjnie, z cyklami analizy, projektowania, implementacji i testowania. To pozwala na ciągłe doskonalenie systemu i dostosowywanie go do zmieniających się wymagań.

Obiektowe projektowanie systemów informatycznych stwarza możliwość tworzenia bardziej modułowego, elastycznego i łatwego w utrzymaniu oprogramowania. Poprzez wykorzystanie koncepcji obiektowych można zwiększyć czytelność kodu, zmniejszyć jego złożoność oraz ułatwić zarządzanie projektem.

### Proszę wymienić i opisać etapy klasycznego cyklu projektowania systemów informatycznych.
1. **Analiza wymagań:**
   - Pierwszym etapem jest analiza potrzeb i wymagań systemu. W tym etapie identyfikuje się cele projektu, określa się funkcje, jakie ma spełniać system oraz zbiera się wymagania od użytkowników końcowych.

2. **Projektowanie:**
   - Na podstawie zebranych wymagań następuje etap projektowania systemu. Projektowanie obejmuje tworzenie architektury systemu, projektowanie interfejsów użytkownika, modelowanie baz danych oraz określanie struktury i zachowań systemu.

3. **Implementacja:**
   - W tym etapie programiści przekształcają projekt w kod komputerowy. Piszą, testują i debugują kod, tworząc oprogramowanie zgodnie z ustalonymi specyfikacjami i wymaganiami.

4. **Testowanie:**
   - Po zakończeniu implementacji następuje etap testowania oprogramowania. Testy mają na celu sprawdzenie, czy system działa zgodnie z oczekiwaniami, czy nie ma w nim błędów, a także czy spełnia wymagania użytkowników.

5. **Wdrożenie:**
   - Po zakończeniu testów i uzyskaniu akceptacji od klienta system jest wdrażany, czyli uruchamiany w środowisku produkcyjnym. Wdrażanie może obejmować instalację oprogramowania, szkolenie użytkowników oraz przeprowadzenie migracji danych.

6. **Utrzymanie:**
   - Ostatni etap to utrzymanie systemu, czyli zapewnienie jego ciągłej pracy, wsparcie użytkowników, naprawa błędów, aktualizacje oprogramowania oraz ewentualne dostosowanie do zmieniających się potrzeb i wymagań użytkowników.

Cykl życia oprogramowania może mieć różne warianty i modyfikacje, w zależności od specyfiki projektu i preferencji zespołu programistycznego. Ważne jest jednak, aby każdy etap był starannie przemyślany i wykonany zgodnie z ustalonymi procedurami, co zapewnia jakość i skuteczność finalnego produktu.

### Proszę omówić i porównać architektury systemów komputerowych typu peer to peer oraz klient-serwer.

Architektura typu peer-to-peer (P2P) oraz klient-serwer są dwoma głównymi modelami architektonicznymi wykorzystywanymi w systemach komputerowych. Oto omówienie i porównanie obu tych architektur:

#### Architektura typu Peer-to-Peer (P2P):

1. **Charakterystyka:**
   - W architekturze P2P każdy komputer w sieci, zwany węzłem, może pełnić zarówno rolę klienta, jak i serwera. Węzły są połączone bezpośrednio między sobą, co umożliwia bezpośrednią komunikację i wymianę danych między nimi.

2. **Brak centralnego serwera:**
   - W architekturze P2P nie ma centralnego serwera zarządzającego ruchem ani dystrybucją danych. Każdy węzeł jest równorzędny i ma taką samą rolę w sieci.

3. **Elastyczność i skalowalność:**
   - Architektura P2P jest elastyczna i łatwo skalowalna, ponieważ nowe węzły mogą być łatwo dodawane do sieci, a usługi są dystrybuowane między wszystkimi węzłami.

4. **Odporność na awarie:**
   - Dzięki brakowi centralnego punktu awaria jednego węzła nie powoduje całkowitej awarii systemu. Pozostałe węzły mogą nadal funkcjonować i wymieniać się informacjami.

5. **Przykład zastosowania:**
   - Sieci P2P są często wykorzystywane do udostępniania plików, komunikacji bezpośredniej między użytkownikami (np. VoIP), a także do obliczeń rozproszonych.

#### Architektura typu Klient-Serwer:

1. **Charakterystyka:**
   - W architekturze klient-serwer komunikacja odbywa się między klientem (aplikacją kliencką) a serwerem (aplikacją serwerową). Klient wysyła żądania do serwera, a serwer udziela odpowiedzi.

2. **Centralny serwer:**
   - Architektura klient-serwer opiera się na istnieniu centralnego serwera, który zarządza zasobami i usługami oraz odpowiada na żądania klientów.

3. **Zależność od serwera:**
   - Klienci nie mogą bezpośrednio komunikować się między sobą w architekturze klient-serwer. Wszelkie komunikaty muszą być przekazywane przez serwer, co może prowadzić do obciążenia sieci w przypadku dużego ruchu.

4. **Prostota zarządzania:**
   - Architektura klient-serwer jest łatwa w zarządzaniu, ponieważ wszystkie zasoby i usługi znajdują się w jednym miejscu - na serwerze. Jest to przydatne w przypadku kontroli dostępu i monitorowania.

5. **Przykład zastosowania:**
   - Architektura klient-serwer jest szeroko stosowana w różnych aplikacjach, takich jak strony internetowe (serwer WWW), poczta elektroniczna (serwer poczty), bazy danych (serwer baz danych) czy też gry sieciowe (serwer gier).

#### Porównanie:

- **Kontrola:** W architekturze klient-serwer kontrola nad zasobami i usługami leży w rękach serwera, podczas gdy w architekturze P2P każdy węzeł ma kontrolę nad swoimi zasobami.
  
- **Skalowalność:** Architektura P2P jest bardziej elastyczna i skalowalna, podczas gdy architektura klient-serwer może być bardziej ograniczona przez zdolność serwera do obsługi dużej liczby klientów.
  
- **Bezpieczeństwo:** Architektura klient-serwer może oferować lepsze bezpieczeństwo, ponieważ serwer może kontrolować dostęp do danych. W architekturze P2P bezpieczeństwo może być bardziej skomplikowane ze względu na brak centralnej kontroli.

Ostatecznie wybór między architekturą klient-serwer a P2P zależy od konkretnych wymagań i charakterystyki projektowanego systemu oraz preferencji dotyczących elastyczności, kontroli i skalowalności.

## Proszę wyjaśnić i omówić proces projektowania baz danych w kontekście bezpieczeństwa informacji.

Proces projektowania baz danych w kontekście bezpieczeństwa informacji jest kluczowym elementem zapewnienia ochrony danych przechowywanych w systemach informatycznych. Oto wyjaśnienie i omówienie tego procesu:

1. **Analiza wymagań dotyczących bezpieczeństwa:**
   - Pierwszym krokiem jest identyfikacja wymagań dotyczących bezpieczeństwa danych. W tym etapie należy określić, jakie informacje są przechowywane w bazie danych, jakie rodzaje zagrożeń mogą wystąpić oraz jakie środki bezpieczeństwa są niezbędne do ich ochrony.

2. **Projektowanie polityki bezpieczeństwa:**
   - Następnie należy opracować politykę bezpieczeństwa, która określa zasady, procedury i praktyki dotyczące ochrony danych w bazie. Polityka bezpieczeństwa powinna uwzględniać aspekty takie jak uwierzytelnianie, autoryzacja, kontrola dostępu, monitorowanie i audytowanie.

3. **Projektowanie modelu dostępu:**
   - Kolejnym krokiem jest projektowanie modelu dostępu, który definiuje, kto ma dostęp do jakich danych i w jaki sposób. Model ten uwzględnia różne role użytkowników (np. administrator, użytkownik końcowy), ich uprawnienia oraz mechanizmy uwierzytelniania i autoryzacji.

4. **Zabezpieczenie dostępu:**
   - W tym etapie należy zaimplementować mechanizmy zabezpieczające dostęp do danych, takie jak hasła, uwierzytelnianie dwuetapowe, certyfikaty SSL/TLS czy też systemy kontroli dostępu, takie jak listy kontroli dostępu (ACL) czy listy kontrolne dostępu (ACL).  

5. **Zabezpieczenie danych:**
   - Należy także zabezpieczyć same dane przechowywane w bazie, stosując metody szyfrowania, zacierania, mieszania lub maskowania danych, szczególnie wrażliwych lub poufnych.

6. **Monitorowanie i audytowanie:**
   - Ważne jest także ciągłe monitorowanie działalności w bazie danych oraz przeprowadzanie audytów, aby wykrywać i śledzić ewentualne naruszenia bezpieczeństwa oraz działać w przypadku ich wystąpienia.

7. **Edukacja i szkolenia:**
   - Nie należy zapominać o edukacji użytkowników i personelu odpowiedzialnego za zarządzanie bazą danych. Szkolenia na temat bezpieczeństwa informacji i korzystania z systemów informatycznych są kluczowe dla zapobiegania incydentom bezpieczeństwa.

8. **Regularne aktualizacje:**
   - W miarę rozwoju technologii i pojawiania się nowych zagrożeń, polityka bezpieczeństwa oraz mechanizmy zabezpieczeń powinny być regularnie aktualizowane i dostosowywane do zmieniających się wymagań i realiów.

Projektowanie baz danych w kontekście bezpieczeństwa informacji wymaga holistycznego podejścia, które uwzględnia zarówno techniczne aspekty zabezpieczeń, jak i politykę, procedury oraz edukację użytkowników. Ważne jest, aby zapewnić kompleksową ochronę danych, minimalizując ryzyko naruszeń bezpieczeństwa i zachowując integralność, poufność i dostępność informacji.

## Proszę omówić i porównać modele relacyjnych i nierelacyjne bazy danych.

Modele relacyjnych i nierelacyjnych baz danych to dwa główne podejścia do przechowywania danych w systemach informatycznych. Oto omówienie i porównanie obu tych modeli:

### Modele relacyjnych baz danych:

1. **Struktura danych:**
   - Relacyjne bazy danych przechowują dane w formie tabel, gdzie każda tabela składa się z wierszy i kolumn, reprezentujących rekordy i atrybuty danych. Dane są ściśle zorganizowane w relacje (tj. tabele), a relacje między nimi są określone za pomocą kluczy obcych.

2. **Język zapytań:**
   - Do komunikacji z relacyjną bazą danych wykorzystuje się język zapytań SQL (Structured Query Language). SQL umożliwia wykonywanie operacji takich jak dodawanie, aktualizacja, usuwanie i zapytania dotyczące danych.

3. **Transakcje:**
   - Relacyjne bazy danych zapewniają wsparcie dla transakcji, co oznacza, że operacje na danych mogą być grupowane w logiczne jednostki, które są wykonywane atomowo (całkowicie lub wcale) i zapewniają spójność danych.

4. **Znormalizacja danych:**
   - W relacyjnych bazach danych stosuje się zasadę normalizacji, która polega na organizowaniu danych w sposób, który minimalizuje redundancję i zapewnia integralność danych poprzez podział na mniejsze, powiązane tabele.

### Modele nierelacyjnych baz danych (NoSQL):

1. **Struktura danych:**
   - Nierelacyjne bazy danych stosują różnorodne struktury danych, takie jak dokumenty (np. w bazach danych typu JSON lub XML), kolumny (np. w bazach danych kolumnowych), grafy (np. w bazach danych grafowych) lub klucze-wartości (np. w bazach danych typu klucz-wartość).

2. **Język zapytań:**
   - W przeciwieństwie do relacyjnych baz danych, nierelacyjne bazy danych niekoniecznie korzystają z języka SQL. Niektóre z nich oferują własne języki zapytań, podczas gdy inne obsługują operacje za pomocą interfejsów programistycznych.

3. **Skalowalność:**
   - Jedną z głównych zalet nierelacyjnych baz danych jest ich skalowalność. Dzięki elastycznym strukturom danych i możliwości rozproszenia danych na wiele węzłów, bazy danych NoSQL mogą obsługiwać duże obciążenia i dużą ilość danych.

4. **Brak znormalizowanej struktury:**
   - W bazach danych NoSQL nie ma konieczności przestrzegania zasad normalizacji danych. Zamiast tego dane mogą być przechowywane w sposób denormalizowany, co może prowadzić do redundancji, ale ułatwia szybszy dostęp do danych.

### Porównanie:

- **Struktura danych:** W relacyjnych bazach danych dane są przechowywane w tabelach związanych relacjami, podczas gdy w bazach danych NoSQL mogą być przechowywane w różnorodnych strukturach, takich jak dokumenty, kolumny, grafy lub klucze-wartości.

- **Język zapytań:** W relacyjnych bazach danych stosuje się język zapytań SQL, podczas gdy w bazach danych NoSQL może być używany różny język zapytań lub interfejsy programistyczne.

- **Transakcje:** Relacyjne bazy danych oferują wsparcie dla transakcji, podczas gdy w bazach danych NoSQL transakcje mogą być mniej konsekwentnie obsługiwane, zwłaszcza w przypadku baz danych typu klucz-wartość.

- **Skalowalność:** Bazy danych NoSQL są zwykle bardziej skalowalne niż relacyjne bazy danych, co oznacza, że mogą obsługiwać większe obciążenia i większą ilość danych.

- **Zastosowania:** Relacyjne bazy danych są często stosowane w tradycyjnych aplikacjach biznesowych, podczas gdy bazy danych NoSQL są bardziej popularne w aplikacjach internetowych, aplikacjach Big Data i aplikacjach wymagających dużej skalowalności.

Ostatecznie wybór między modelem relacyjnych a nierelacyjnym baz danych zależy od konkretnych wymagań projektu, charakteru danych oraz oczekiwanego obciążenia i skalowalności systemu. Każdy z tych modeli ma swoje zalety i ograniczenia, które należy uwzględnić przy projektowaniu systemu.

## Proszę omówić czym jest API, podać przykłady zastosowania.

API (Application Programming Interface) to zestaw definicji, protokołów i narzędzi, które umożliwiają komunikację między różnymi aplikacjami lub serwisami. API określa, w jaki sposób różne komponenty oprogramowania powinny się ze sobą komunikować, jakie dane mogą być wymieniane i jakie operacje mogą być wykonywane.

### Czym jest API?

1. **Definicja interfejsu:** API definiuje sposób, w jaki programy mogą komunikować się ze sobą. Określa strukturę zapytań i odpowiedzi, formaty danych oraz dostępne operacje.

2. **Protokoły komunikacyjne:** API może korzystać z różnych protokołów komunikacyjnych, takich jak HTTP, REST, SOAP, GraphQL, TCP/IP, aby umożliwić przesyłanie danych między aplikacjami.

3. **Narzędzia programistyczne:** API może być udostępniane w postaci bibliotek programistycznych, interfejsów użytkownika (np. interfejsów API internetowych), dokumentacji technicznej i przykładowego kodu.

### Przykłady zastosowania API:

1. **API internetowe (Web API):**
   - Przykładem API internetowego jest API RESTful, które umożliwia komunikację między aplikacjami internetowymi. Na przykład, API RESTful może być wykorzystywane przez aplikację mobilną do pobierania danych z serwera, np. informacji o użytkownikach, produktach, czy też aktualnościach.

2. **API usługowe (Service API):**
   - Firmy często udostępniają API usługowe, aby umożliwić integrację z ich usługami. Na przykład, PayPal oferuje API płatności, które pozwala firmom na akceptowanie płatności online za pośrednictwem swoich aplikacji.

3. **API platformy społecznościowej:**
   - Platformy społecznościowe, takie jak Facebook, Twitter czy Instagram, udostępniają API, które pozwala deweloperom tworzyć aplikacje, które integrują się z ich platformą. Przykładowe zastosowanie to aplikacje, które umożliwiają publikowanie postów na Facebooku, pobieranie danych o użytkownikach czy też analizowanie trendów społecznościowych.

4. **API platformy chmurowej (Cloud API):**
   - Platformy chmurowe, takie jak Amazon Web Services (AWS), Google Cloud Platform (GCP) czy Microsoft Azure, udostępniają API, które umożliwiają zarządzanie zasobami chmury, takimi jak maszyny wirtualne, kontenery, usługi bazodanowe czy też przechowywanie danych.

5. **API aplikacji desktopowych i mobilnych:**
   - Niektóre aplikacje desktopowe i mobilne oferują API, które umożliwiają integrację z innymi aplikacjami lub usługami. Przykładowe zastosowanie to integracja aplikacji z systemem płatności, mapami, czy też usługami lokalizacyjnymi.

API są niezwykle ważne dla współczesnych systemów informatycznych, ponieważ umożliwiają integrację między różnymi aplikacjami i usługami, co pozwala na rozwój innowacyjnych rozwiązań, zwiększa wydajność i usprawnia współpracę między różnymi platformami.

## Różnice między aplikacjami  hybrydowymi a natywnymi w systemach mobilnych

Aplikacje hybrydowe i natywne są dwoma głównymi podejściami do tworzenia aplikacji mobilnych, a każde z nich ma swoje zalety i ograniczenia. Oto różnice między nimi:

### Aplikacje natywne:

1. **Platformowe:**
   - Aplikacje natywne są tworzone specjalnie dla konkretnych platform mobilnych, takich jak iOS (na urządzenia Apple) lub Android. Są one pisane w językach programowania zależnych od platformy, takich jak Swift lub Objective-C dla iOS, oraz Java lub Kotlin dla Androida.

2. **Pełen dostęp do funkcji urządzenia:**
   - Aplikacje natywne mają pełny dostęp do funkcji i możliwości urządzenia, co pozwala na wykorzystanie wszystkich dostępnych funkcji, takich jak aparat fotograficzny, GPS, czujniki, czy też system powiadomień.

3. **Najlepsza wydajność:**
   - Dzięki optymalizacji dla konkretnej platformy, aplikacje natywne zapewniają zazwyczaj najlepszą wydajność i responsywność w porównaniu do innych rodzajów aplikacji.

4. **Integracja z ekosystemem platformy:**
   - Aplikacje natywne mogą korzystać z pełnej integracji z ekosystemem platformy, co obejmuje sklepy aplikacji (App Store dla iOS i Google Play dla Androida), biblioteki, narzędzia deweloperskie i wsparcie.

### Aplikacje hybrydowe:

1. **Jednoczesne działanie na różnych platformach:**
   - Aplikacje hybrydowe są tworzone za pomocą technologii internetowych, takich jak HTML, CSS i JavaScript, a następnie są opakowywane w kontener natywny, który pozwala na ich uruchamianie na różnych platformach mobilnych.

2. **Jednoczesne rozwijanie:**
   - Dzięki użyciu jednego kodu źródłowego, aplikacje hybrydowe mogą być rozwijane jednocześnie dla różnych platform, co pozwala na oszczędność czasu i kosztów.

3. **Mniejsze możliwości dostępu do funkcji urządzenia:**
   - Aplikacje hybrydowe mają ograniczony dostęp do funkcji urządzenia w porównaniu do aplikacji natywnych. Niektóre zaawansowane funkcje mogą być trudne do osiągnięcia lub niemożliwe do zrealizowania.

4. **Mniejsza wydajność:**
   - Ze względu na dodatkową warstwę abstrakcji, aplikacje hybrydowe mogą być mniej wydajne niż aplikacje natywne, zwłaszcza w przypadku bardziej złożonych i wymagających aplikacji.

5. **Ograniczona integracja z ekosystemem platformy:**
   - Aplikacje hybrydowe mogą mieć ograniczoną integrację z ekosystemem platformy, co może wpływać na dostępność funkcji, narzędzi i wsparcia dla deweloperów.

### Podsumowanie:

- Aplikacje natywne oferują najlepszą wydajność, pełen dostęp do funkcji urządzenia i integrację z ekosystemem platformy, ale wymagają oddzielnego kodu dla każdej platformy.
- Aplikacje hybrydowe umożliwiają jednoczesne rozwijanie dla różnych platform, co może być korzystne dla niektórych projektów, ale mogą mieć ograniczenia w dostępie do funkcji urządzenia i wydajności.

## Proszę wymienić i omówić sprzętowe i programowe składniki sieci komputerowych.
Aplikacje hybrydowe i natywne są dwoma głównymi podejściami do tworzenia aplikacji mobilnych, a każde z nich ma swoje zalety i ograniczenia. Oto różnice między nimi:

### Aplikacje natywne:

1. **Platformowe:**
   - Aplikacje natywne są tworzone specjalnie dla konkretnych platform mobilnych, takich jak iOS (na urządzenia Apple) lub Android. Są one pisane w językach programowania zależnych od platformy, takich jak Swift lub Objective-C dla iOS, oraz Java lub Kotlin dla Androida.

2. **Pełen dostęp do funkcji urządzenia:**
   - Aplikacje natywne mają pełny dostęp do funkcji i możliwości urządzenia, co pozwala na wykorzystanie wszystkich dostępnych funkcji, takich jak aparat fotograficzny, GPS, czujniki, czy też system powiadomień.

3. **Najlepsza wydajność:**
   - Dzięki optymalizacji dla konkretnej platformy, aplikacje natywne zapewniają zazwyczaj najlepszą wydajność i responsywność w porównaniu do innych rodzajów aplikacji.

4. **Integracja z ekosystemem platformy:**
   - Aplikacje natywne mogą korzystać z pełnej integracji z ekosystemem platformy, co obejmuje sklepy aplikacji (App Store dla iOS i Google Play dla Androida), biblioteki, narzędzia deweloperskie i wsparcie.

### Aplikacje hybrydowe:

1. **Jednoczesne działanie na różnych platformach:**
   - Aplikacje hybrydowe są tworzone za pomocą technologii internetowych, takich jak HTML, CSS i JavaScript, a następnie są opakowywane w kontener natywny, który pozwala na ich uruchamianie na różnych platformach mobilnych.

2. **Jednoczesne rozwijanie:**
   - Dzięki użyciu jednego kodu źródłowego, aplikacje hybrydowe mogą być rozwijane jednocześnie dla różnych platform, co pozwala na oszczędność czasu i kosztów.

3. **Mniejsze możliwości dostępu do funkcji urządzenia:**
   - Aplikacje hybrydowe mają ograniczony dostęp do funkcji urządzenia w porównaniu do aplikacji natywnych. Niektóre zaawansowane funkcje mogą być trudne do osiągnięcia lub niemożliwe do zrealizowania.

4. **Mniejsza wydajność:**
   - Ze względu na dodatkową warstwę abstrakcji, aplikacje hybrydowe mogą być mniej wydajne niż aplikacje natywne, zwłaszcza w przypadku bardziej złożonych i wymagających aplikacji.

5. **Ograniczona integracja z ekosystemem platformy:**
   - Aplikacje hybrydowe mogą mieć ograniczoną integrację z ekosystemem platformy, co może wpływać na dostępność funkcji, narzędzi i wsparcia dla deweloperów.

### Podsumowanie:

- Aplikacje natywne oferują najlepszą wydajność, pełen dostęp do funkcji urządzenia i integrację z ekosystemem platformy, ale wymagają oddzielnego kodu dla każdej platformy.
- Aplikacje hybrydowe umożliwiają jednoczesne rozwijanie dla różnych platform, co może być korzystne dla niektórych projektów, ale mogą mieć ograniczenia w dostępie do funkcji urządzenia i wydajności.

## Proszę scharakteryzować rolę FireWalla w sieci, podać przykłady zastosowania

Firewall jest to rodzaj systemu lub urządzenia sieciowego, które ma za zadanie kontrolować ruch sieciowy między siecią wewnętrzną a zewnętrzną, zapewniając bezpieczeństwo sieci poprzez filtrowanie i monitorowanie danych. Oto charakterystyka roli firewalla w sieci oraz przykłady zastosowania:

### Rola Firewala w sieci:

1. **Filtrowanie ruchu sieciowego:**
   - Firewall analizuje ruch sieciowy na podstawie określonych reguł i polityk bezpieczeństwa, decydując, które pakiety danych są dozwolone, a które powinny być zablokowane lub odrzucone.

2. **Zabezpieczenie przed atakami z zewnątrz:**
   - Firewall chroni sieć przed różnymi rodzajami ataków z zewnątrz, takimi jak ataki DDoS (Distributed Denial of Service), próby włamań, skany portów czy też ataki typu malware.

3. **Kontrola dostępu:**
   - Firewall umożliwia kontrolę dostępu do zasobów sieciowych, określając, które urządzenia lub użytkownicy mają prawo do dostępu do określonych zasobów sieciowych.

4. **Monitorowanie ruchu sieciowego:**
   - Firewall monitoruje ruch sieciowy w czasie rzeczywistym, rejestrując i analizując zdarzenia, które mogą wskazywać na nieprawidłowości lub potencjalne zagrożenia.

5. **Zabezpieczenie przed wyciekiem danych:**
   - Firewalle mogą zapewniać zabezpieczenie przed wyciekiem danych poprzez kontrolę i filtrowanie ruchu wychodzącego z sieci, uniemożliwiając nieautoryzowany transfer poufnych informacji.

### Przykłady zastosowania Firewala:

1. **Firewall sieciowy:**
   - Firewall sieciowy jest umieszczany pomiędzy siecią lokalną a Internetem, gdzie kontroluje ruch przychodzący i wychodzący z sieci lokalnej. Jest to jeden z najczęstszych rodzajów firewalloów stosowanych w sieciach firmowych i domowych.

2. **Firewall aplikacyjny (aplikacyjny):**
   - Firewall aplikacyjny działa na poziomie aplikacji, analizując dane przesyłane między aplikacjami i blokując niepożądane treści lub ataki. Jest często stosowany do ochrony serwerów WWW przed atakami typu SQL injection, XSS (Cross-Site Scripting) czy też atakami CSRF (Cross-Site Request Forgery).

3. **Firewall hosta:**
   - Firewall hosta działa na samym urządzeniu (hostu), kontrolując ruch sieciowy między aplikacjami działającymi na tym urządzeniu a resztą sieci. Jest często wykorzystywany w systemach operacyjnych, aby zapewnić dodatkową warstwę zabezpieczeń na poziomie pojedynczego urządzenia.

4. **Firewall bramy:**
   - Firewall bramy jest umieszczany na granicy między dwiema sieciami, takimi jak sieć wewnętrzna a sieć zewnętrzna, aby kontrolować ruch między nimi. Jest stosowany w dużych organizacjach, gdzie jest pierwszą linią obrony przed atakami z zewnątrz.

Firewall jest kluczowym elementem infrastruktury sieciowej, który pomaga w zapewnieniu bezpieczeństwa i prywatności danych poprzez kontrolę i monitorowanie ruchu sieciowego.

## Efektywny transfer informacji w sieciach komputerowych, podać przykłady realizacji takiego przepływu dla wybranej technologii sieciowej.

Efektywny transfer informacji w sieciach komputerowych jest kluczowym elementem zapewnienia szybkiego i niezawodnego przesyłania danych. Istnieje wiele technologii sieciowych, które umożliwiają efektywny transfer informacji, a jedną z nich jest protokół TCP/IP wykorzystywany w sieciach internetowych. Oto przykłady realizacji efektywnego przepływu danych dla technologii sieciowej opartej na protokole TCP/IP:

1. **Transmisja plików za pomocą FTP (File Transfer Protocol):**
   - FTP jest protokołem wykorzystywanym do przesyłania plików między hostami w sieci TCP/IP. Dzięki FTP możliwe jest szybkie i niezawodne przesyłanie dużych plików między serwerem a klientem. Przesyłanie danych za pomocą FTP może być efektywne ze względu na zastosowanie specjalnych algorytmów kompresji danych oraz mechanizmów kontroli błędów, które zapewniają integralność danych.

2. **Strumieniowanie wideo za pomocą protokołu RTP (Real-Time Transport Protocol):**
   - RTP jest protokołem służącym do przesyłania strumieni multimediów, takich jak wideo i audio, w czasie rzeczywistym przez sieć TCP/IP. Dzięki RTP możliwe jest efektywne przesyłanie strumieni wideo z minimalnym opóźnieniem i utratą danych. Protokół ten wspiera również mechanizmy kontroli przepływu, dzięki czemu strumienie multimediów są przesyłane w sposób optymalny, nawet przy zmiennym obciążeniu sieci.

3. **Protokół HTTP/2 dla przesyłania stron internetowych:**
   - HTTP/2 jest nowszą wersją protokołu HTTP, która wprowadza szereg usprawnień w zakresie transferu danych. Dzięki zastosowaniu technik takich jak multiplexing, kompresja nagłówków i priorytetyzacja zasobów, HTTP/2 umożliwia efektywny transfer danych podczas przeglądania stron internetowych. Protokół ten redukuje opóźnienia w transferze danych, co przekłada się na szybsze ładowanie się stron internetowych.

4. **Tunelowanie VPN (Virtual Private Network):**
   - VPN to technologia pozwalająca na tworzenie bezpiecznego tunelu komunikacyjnego między dwoma punktami końcowymi w sieci TCP/IP. Wirtualna sieć prywatna umożliwia efektywny transfer danych poprzez szyfrowanie ruchu i zapewnienie poufności danych. Przesyłanie danych za pośrednictwem tunelu VPN może być efektywne w przypadku konieczności zapewnienia bezpiecznego i prywatnego transferu informacji, zwłaszcza w przypadku zdalnego dostępu do zasobów sieciowych.

Wszystkie powyższe przykłady wykorzystują protokół TCP/IP, który jest podstawą funkcjonowania sieci internetowej. Dzięki zastosowaniu odpowiednich technologii i protokołów, transfer informacji w sieciach komputerowych może być wydajny, niezawodny i bezpieczny.

## Proszę wymienić podstawowe protokoły routingu i metryki w nich stosowane.


1. Protokół RIP (Routing Information Protocol).

    Protokół typu dystans-wektor (distance-vector). Ze względu na niskie wymagania sprzętowe
    może być używany przez wszystkie routery. Router z uruchomionym protokołem RIP wysyła
    do swoich bezpośrednich sąsiadów zawartość swojej tablicy routingu w określonych, stałych
    przedziałach czasu, standardowo co 30 s. Router po przyjęciu aktualizacji od sąsiada
    porównuje ją z własną tablicą routingu i w razie konieczności uaktualnia ją. W tablicy
    routingu znajdują się najlepsze trasy do wszystkich sieci. Jako miarę jakości trasy w protokole
    RIP przyjęto liczbę przeskoków (hopów) między routerami, jakie pakiet musi wykonać, aby
    dotrzeć do celu. Liczba przeskoków jest ograniczona do 15, dlatego RIP nie może być
    stosowany w bardzo dużych sieciach. RIP dobrze spełnia swoje zadanie w sieciach
    jednorodnych, tzn. takich, w których wszystkie łącza mają jednakową przepustowość.


2. Protokół OSPF (Open Shortest Path First).
    Podobnie jak RIP jest protokołem otwartym, tzn. że jego specyfikacja jest ogólnie dostępna.
    Jest to protokół typu stanu łącza (link-state), wykorzystujący algorytm SPF (Dijkstry)
    do obliczania najkrótszych ścieżek. Metryką w protokole OSPF jest koszt powiązany
    z przepustowością łączy (im większa przepustowość, tym niższy koszt). Protokół ten
    przeznaczony jest do dużych sieci. Sieć taka może być podzielona na obszary, w których
    routery wymieniają się wzajemnie krótkimi komunikatami LSA (Link-State Advertisement).
    Na podstawie tych komunikatów każdy router zbiera informacje o całej topologii obszaru,
    a następnie za pomocą algorytmu SPF oblicza najlepsze trasy do wszystkich sieci. Każdy
    obszar musi być dołączony do obszaru 0 (szkieletowego), co pozwala na połączenie sieci
    w jedną całość. Zmiany dokonane w jednym z obszarów nie powodują konieczności
    uruchomienia algorytmu SPF w pozostałych obszarach. Obliczanie ścieżek w poszczególnych
    obszarach jest łatwiejsze i wymaga mniejszego nakładu obliczeniowego. Ze względu
    na konieczność dokonywania skomplikowanych obliczeń, protokół OSPF ma większe
    wymagania sprzętowe niż RIP.


3. Protokół IGRP (Interior-Gateway Routing Protocol) i jego następca EIGRP (Extended
IGRP).

    Zostały opracowane przez firmę CISCO. IGRP podobnie jak RIP jest protokołem typu
    dystans-wektor, ale wykorzystuje jako metrykę różne kombinacje czterech miar: opóźnienia,
    szerokości pasma (przepustowości), obciążenia i niezawodności. EIGRP jest protokołem
    hybrydowym – posiada najlepsze cechy algorytmów routingu z wykorzystaniem wektora
    odległości i według stanu łącza. EIGRP do wyznaczania tras stosuje algorytm DUAL
    (Diffusing – Update ALgorithm). Jest on zalecany do stosowania przez CISCO.

2. **Metryki routingu:**

   - **Hop Count:** Metryka oparta na liczbie skoków (hop count) między routerem źródłowym a docelowym. W protokołach wektorów odległości, takich jak RIP, metryka ta zwykle wyrażana jest w liczbie przeskoków (hop count) przez sieć.
   
   - **Bandwidth:** Metryka oparta na przepustowości łącza. W protokołach stanu łącza, takich jak OSPF i EIGRP, przepustowość łącza jest jednym z czynników branych pod uwagę przy obliczaniu najlepszych tras.
   
   - **Delay:** Metryka oparta na opóźnieniu (delay) transmisji pakietów między routerami. Im mniejsze opóźnienie, tym lepsza jakość trasy. Wiele protokołów routingu uwzględnia opóźnienie jako czynnik decydujący o wyborze trasy.
   
   - **Cost:** Metryka oparta na koszcie przesyłania danych między routerami. Koszt może być zdefiniowany jako kombinacja różnych czynników, takich jak przepustowość, opóźnienie, zużycie energii itp. W EIGRP, na przykład, metryka trasy jest wyliczana jako suma różnych czynników, które określają jej koszt.

Te metryki są wykorzystywane przez protokoły routingu do obliczania najlepszych tras i wybierania optymalnych ścieżek w sieci. Różne protokoły routingu mogą używać różnych metryk i algorytmów do podejmowania decyzji routingu.

## Paradygmaty programowania strukturalnego i obiektowego.

Paradygmaty programowania strukturalnego i obiektowego są dwoma głównymi podejściami do projektowania i tworzenia programów komputerowych. Oto krótkie omówienie obu tych paradygmatów:

### Programowanie strukturalne:

1. **Podział programu na procedury:** W programowaniu strukturalnym programy są organizowane w formie procedur lub funkcji, które wykonują konkretne zadania. Procedury te są wywoływane z głównego programu w określonych momentach.

2. **Kontrola przepływu danych:** W programowaniu strukturalnym istnieje linearna kontrola przepływu danych, co oznacza, że wykonanie programu przechodzi od jednej instrukcji do następnej w sposób sekwencyjny.

3. **Używanie instrukcji warunkowych i pętli:** Programowanie strukturalne opiera się na instrukcjach warunkowych (if-else) oraz pętlach (for, while), które pozwalają na kontrolę przepływu programu w zależności od warunków logicznych.

4. **Podział na moduły:** Programy strukturalne są zwykle podzielone na mniejsze, bardziej czytelne moduły, co ułatwia zarządzanie kodem i jego późniejsze utrzymanie.

### Programowanie obiektowe:

1. **Koncepcja obiektów:** W programowaniu obiektowym programy są modelowane wokół obiektów, które reprezentują konkretne byty lub rzeczywistość. Każdy obiekt ma swoje własne cechy (atrybuty) oraz zachowania (metody).

2. **Enkapsulacja:** Enkapsulacja polega na ukrywaniu wewnętrznych detali implementacyjnych obiektu i udostępnianiu jedynie interfejsu, który umożliwia manipulowanie jego stanem i zachowaniem.

3. **Dziedziczenie:** Dziedziczenie pozwala na tworzenie nowych klas na podstawie istniejących klas, co umożliwia ponowne wykorzystanie kodu oraz tworzenie hierarchii klas.

4. **Polimorfizm:** Polimorfizm pozwala na przypisywanie różnych zachowań do tych samych metod w różnych klasach. W praktyce oznacza to, że ta sama metoda może być wywoływana na różnych obiektach i zachowywać się inaczej, w zależności od typu obiektu.

5. **Klasy i obiekty:** Programy obiektowe są organizowane wokół klas, które są szablonami definiującymi strukturę i zachowanie obiektów. Obiekty są instancjami klas, które posiadają określone wartości atrybutów i mogą wywoływać metody zdefiniowane w klasie.

Programowanie obiektowe często uważane jest za bardziej elastyczne i skalowalne niż programowanie strukturalne, ponieważ umożliwia lepszą organizację kodu, ułatwia ponowne wykorzystanie i zapewnia większą abstrakcję i modularność. Jednak oba te paradygmaty mają swoje miejsce w dzisiejszym świecie programowania i mogą być stosowane w zależności od konkretnych wymagań projektowych i preferencji programisty.


## 
Diagram przypadków użycia (USE CASE) jest narzędziem modelowania używanym w inżynierii wymagań i projektowaniu systemów informatycznych. Jest to graficzne przedstawienie interakcji pomiędzy aktorami (użytkownikami zewnętrznymi lub systemami zewnętrznymi) a systemem, prezentujące funkcjonalności systemu z punktu widzenia użytkownika. Oto krótkie omówienie do czego służy diagram USE CASE oraz przykład jego zastosowania.

### Zastosowanie diagramu USE CASE:

1. **Definiowanie wymagań systemu:** Diagram przypadków użycia pomaga zidentyfikować i zrozumieć potrzeby użytkowników oraz funkcjonalności, które system powinien zapewnić, co pozwala na precyzyjne zdefiniowanie wymagań systemowych.

2. **Komunikacja między interesariuszami:** Diagram USE CASE jest narzędziem komunikacji między zespołem projektowym a interesariuszami, umożliwiając przedstawienie funkcjonalności systemu w sposób zrozumiały dla wszystkich zaangażowanych stron.

3. **Projektowanie interfejsu użytkownika:** Na podstawie diagramu USE CASE projektanci mogą projektować interfejs użytkownika, uwzględniając funkcje, które powinny być dostępne dla użytkowników oraz interakcje między nimi a systemem.

4. **Testowanie systemu:** Diagram przypadków użycia może służyć jako podstawa do opracowania przypadków testowych, które mogą być wykorzystane podczas testowania systemu, aby upewnić się, że wszystkie funkcje są zaimplementowane zgodnie z oczekiwaniami użytkowników.

### Przykład diagramu USE CASE:

Poniżej znajduje się prosty przykład diagramu przypadków użycia dla systemu bibliotecznego:

```
 _____________________________
|           Biblioteka         |
|_____________________________|
| - Zarządzanie książkami     |
| - Wypożyczanie książek      |
| - Przedłużanie wypożyczenia |
| - Rezerwacja książek        |
|_____________________________|

 _____________________________
|          Bibliotekarz        |
|_____________________________|
| - Zarządzanie książkami     |
| - Wypożyczanie książek      |
| - Przedłużanie wypożyczenia |
| - Rezerwacja książek        |
|_____________________________|

 _____________________________
|             Użytkownik       |
|_____________________________|
| - Przeglądanie katalogu     |
| - Wyszukiwanie książek      |
| - Rezerwacja książek        |
|_____________________________|
```

W tym przykładzie mamy trzy główne przypadki użycia: zarządzanie książkami, wypożyczanie książek i rezerwacja książek. Aktorami są bibliotekarz i użytkownik. Każdy z nich ma swoje uprawnienia i możliwości w systemie bibliotecznym. Na przykład, zarówno bibliotekarz, jak i użytkownik mogą wypożyczyć książki, ale tylko bibliotekarz może zarządzać książkami w systemie.


## Proszę opisać dwie przykładowe usługi wchodzące w skład chmury obliczeniowej.

1. **Azure Virtual Machines:**
   - Usługa Azure Virtual Machines umożliwia użytkownikom tworzenie i zarządzanie wirtualnymi maszynami w chmurze. Użytkownicy mogą wybierać spośród różnych systemów operacyjnych (takich jak Windows Server, Linux), wybierać odpowiednią konfigurację sprzętową (CPU, pamięć, dyski SSD/HDD) oraz skalować zasoby wirtualnej maszyny w zależności od potrzeb. Ta elastyczność pozwala na dostosowanie środowiska obliczeniowego do różnorodnych zastosowań, od małych serwerów testowych po zaawansowane aplikacje produkcyjne. Dodatkowo, Azure oferuje usługę automatycznego zarządzania skalowaniem, co pozwala na dynamiczne dostosowywanie zasobów w oparciu o obciążenie i potrzeby aplikacji.

2. **Azure Blob Storage:**
   - Azure Blob Storage to usługa przechowywania obiektowego w chmurze, która umożliwia przechowywanie i zarządzanie dużymi zbiorami danych, takimi jak pliki, multimediów, kopie zapasowe, archiwa i wiele innych. Użytkownicy mogą przechowywać ogromne ilości danych w postaci nieustrukturyzowanej i uzyskiwać do nich dostęp z dowolnego miejsca na świecie za pomocą Internetu. Usługa ta oferuje różne opcje dostępności (dostępna, zimna, archiwalna), umożliwia szyfrowanie danych w spoczynku i w ruchu oraz zapewnia wysoką skalowalność i niezawodność. Ponadto, Azure Blob Storage integruje się z wieloma innymi usługami Azure, co pozwala na tworzenie zaawansowanych rozwiązań, takich jak analizy danych, przetwarzanie w czasie rzeczywistym i wiele innych.

## Różnice pomiędzy algorytmami genetycznymi a tradycyjnymi metodami optymalizacyjnymi.
Algorytmy genetyczne (AG) i tradycyjne metody optymalizacyjne różnią się w kilku kluczowych aspektach. Oto główne różnice pomiędzy nimi:

1. **Zastosowanie metod:**
   - Metody tradycyjne, takie jak metoda gradientowa, metoda sympleksowa, czy metoda zbioru siatek, często stosuje się do rozwiązywania problemów optymalizacyjnych w oparciu o iteracyjne poprawianie rozwiązania poprzez analizę gradientu funkcji celu. Z kolei algorytmy genetyczne są wykorzystywane głównie w problemach optymalizacji globalnej, w których przestrzeń rozwiązań jest duża i/lub złożona, a także w problemach, gdzie funkcja celu jest nieliniowa, nieregularna lub wielomodalna.

2. **Sposób działania:**
   - Metody tradycyjne zwykle operują na pojedynczym rozwiązaniu, które jest iteracyjnie poprawiane w kierunku optymalizacji. Algorytmy genetyczne działają na populacji potencjalnych rozwiązań, które ewoluują w czasie poprzez proces selekcji, krzyżowania i mutacji, przy czym najlepsze rozwiązania są wybierane do dalszej reprodukcji.

3. **Losowość:**
   - W metodach tradycyjnych, typowo stosuje się metody deterministyczne, które dążą do znalezienia najlepszego rozwiązania na podstawie analizy funkcji celu. W przypadku algorytmów genetycznych, losowość jest kluczowym elementem, ponieważ proces ewolucji populacji opiera się na losowych operacjach selekcji, krzyżowania i mutacji.

4. **Złożoność problemów:**
   - Metody tradycyjne często są skuteczne w rozwiązywaniu prostszych problemów optymalizacyjnych, gdzie funkcja celu jest dobrze określona i ma jednoznaczne optimum lokalne. Algorytmy genetyczne są bardziej skuteczne w rozwiązywaniu złożonych problemów optymalizacyjnych, które mogą mieć wiele lokalnych optimów i wymagają przeszukiwania przestrzeni rozwiązań w celu znalezienia najlepszego rozwiązania globalnego.

5. **Dostosowanie do zmian:**
   - Algorytmy genetyczne mają tendencję do lepszego radzenia sobie z dynamicznymi środowiskami, w których warunki optymalizacji mogą się zmieniać w czasie. Ze względu na ich populacyjną naturę, mogą szybciej dostosowywać się do zmian w funkcji celu lub warunkach problemu niż tradycyjne metody.

Podsumowując, mimo że metody tradycyjne mogą być skuteczne w prostszych problemach optymalizacyjnych, algorytmy genetyczne są często wybierane do rozwiązywania złożonych problemów optymalizacyjnych, gdzie istnieje potrzeba przeszukiwania przestrzeni rozwiązań w poszukiwaniu najlepszego rozwiązania globalnego. Ich elastyczność i zdolność do pracy w dynamicznych środowiskach czyni je atrakcyjnymi narzędziami w dziedzinach takich jak inżynieria, nauki przyrodnicze, ekonomia i informatyka.

## Proszę wyjaśnić i opisać pojęcie sztucznej sieci neuronowej.

Sztuczna sieć neuronowa (SSN) to model obliczeniowy, który jest inspirowany biologicznymi sieciami neuronowymi, które stanowią mózgi zwierząt. SSN jest systemem "połączonych" jednostek, zwanych neuronami, które przetwarzają informacje za pomocą dynamicznego stanu odpowiedzi na wejście zewnętrzne.

SSN składa się z trzech głównych typów warstw:
1. **Warstwa wejściowa**: Ta warstwa odbiera sygnały wejściowe i przekazuje je do sieci.
2. **Warstwy ukryte**: Te warstwy wykonują większość obliczeń wymaganych przez sieć.
3. **Warstwa wyjściowa**: Ta warstwa odbiera sygnały z warstw ukrytych i przekształca je w format, który jest użyteczny dla ich zastosowania.

Każdy neuron w sieci jest połączony z innymi przez połączenia, które nazywane są wagami. Wagi te są używane do obliczania wyniku dla danego neuronu, który jest następnie przekazywany przez funkcję aktywacji.

Sztuczne sieci neuronowe są stosowane w wielu dziedzinach, takich jak rozpoznawanie obrazów, przetwarzanie języka naturalnego, rozpoznawanie mowy, i wiele innych. Są one podstawą wielu zaawansowanych technologii sztucznej inteligencji. 

Ważne jest jednak, aby pamiętać, że mimo iż SSN są inspirowane biologicznymi sieciami neuronowymi, są one znacznie uproszczone i nie odzwierciedlają pełnej złożoności prawdziwego mózgu.

## Pojęcie architektury komputera. Podać zasady działania podzespołów bazowych komputera.

Architektura komputera odnosi się do struktury oraz organizacji podzespołów i elementów składowych komputera, które współpracują ze sobą w celu wykonywania operacji obliczeniowych i przetwarzania danych. Podstawowe zasady działania podzespołów bazowych komputera obejmują:

1. **Procesor (CPU - Central Processing Unit):**
   - Procesor jest mózgiem komputera i odpowiada za wykonywanie operacji obliczeniowych i sterowanie innymi podzespołami. Procesor pobiera instrukcje z pamięci operacyjnej (RAM), przetwarza je i wydaje odpowiednie polecenia wykonawcze.

2. **Pamięć operacyjna (RAM - Random Access Memory):**
   - RAM jest pamięcią, która przechowuje dane i instrukcje, na których aktualnie pracuje procesor. Dostęp do danych w pamięci RAM jest szybki, ale ulotny, co oznacza, że dane są tracone po wyłączeniu zasilania komputera.

3. **Pamięć masowa (np. dysk twardy, SSD - Solid State Drive):**
   - Pamięć masowa przechowuje dane trwale, nawet po wyłączeniu zasilania komputera. Na przykład dysk twardy lub SSD przechowuje system operacyjny, aplikacje i pliki użytkowników. Dane z pamięci masowej są odczytywane i zapisywane w sposób sekwencyjny lub losowy.

4. **Karta graficzna (GPU - Graphics Processing Unit):**
   - Karta graficzna jest odpowiedzialna za przetwarzanie grafiki i generowanie obrazu na monitorze. Jest szczególnie istotna w grach komputerowych, projektowaniu graficznym, czy przetwarzaniu wideo.

5. **Dysk optyczny (np. napęd CD/DVD/Blu-ray):**
   - Dysk optyczny służy do odczytu i zapisu danych na nośnikach optycznych, takich jak płyty CD, DVD lub Blu-ray.

6. **Płyta główna (ang. motherboard):**
   - Płyta główna jest platformą, na której montowane są pozostałe podzespoły komputera. Zapewnia interfejsy komunikacyjne i zasilanie dla wszystkich podzespołów oraz zawiera elementy takie jak złącza PCI, złącza pamięci, czy porty USB.

7. **Zasilacz:**
   - Zasilacz dostarcza energię elektryczną do wszystkich podzespołów komputera, zapewniając stabilne napięcia i prądy.

8. **Interfejsy komunikacyjne (np. porty USB, HDMI, Ethernet):**
   - Interfejsy komunikacyjne umożliwiają podłączanie zewnętrznych urządzeń do komputera oraz wymianę danych z innymi urządzeniami, sieciami lub internetem.

Podstawowe zasady działania tych podzespołów bazowych są skoordynowane w taki sposób, aby umożliwić wydajne przetwarzanie danych, komunikację między elementami komputera oraz obsługę różnorodnych zadań i operacji przez użytkownika.

## Sposób współpracy komputera z urządzeniami wejścia/wyjścia.
Sposób współpracy komputera z urządzeniami wejścia/wyjścia (I/O - Input/Output) odbywa się poprzez odpowiednie interfejsy i protokoły komunikacyjne. Oto ogólny opis sposobu współpracy:

1. **Komunikacja z urządzeniami wejścia:**
   - Urządzenia wejścia, takie jak klawiatura, myszka, skaner czy mikrofon, przekazują dane wejściowe do komputera. Procesor komputera odbiera dane wejściowe z tych urządzeń za pośrednictwem odpowiednich kontrolerów interfejsów wejścia, takich jak porty USB, PS/2, czy Bluetooth. Dane wejściowe są następnie przetwarzane przez system operacyjny i odpowiednie aplikacje w celu wykonywania określonych operacji.

2. **Komunikacja z urządzeniami wyjścia:**
   - Urządzenia wyjścia, takie jak monitor, drukarka, głośniki czy dysk zewnętrzny, odbierają dane wyjściowe z komputera. Dane te są przesyłane z komputera za pomocą odpowiednich interfejsów wyjścia, takich jak porty HDMI, DisplayPort, USB czy audio. Urządzenia te interpretują dane wyjściowe i generują odpowiednią reakcję, np. wyświetlanie obrazu na monitorze, drukowanie dokumentu, czy odtwarzanie dźwięku.

3. **Sterowniki urządzeń:**
   - Aby komputer mógł współpracować z różnymi urządzeniami wejścia/wyjścia, potrzebne są odpowiednie sterowniki urządzeń. Sterowniki to oprogramowanie, które umożliwia komunikację między systemem operacyjnym a konkretnymi urządzeniami. Kiedy urządzenie jest podłączane do komputera, system operacyjny automatycznie wykrywa je i ładuje odpowiedni sterownik, który zapewnia obsługę urządzenia.

4. **Protokoły komunikacyjne:**
   - Komunikacja między komputerem a urządzeniami wejścia/wyjścia odbywa się zazwyczaj za pomocą odpowiednich protokołów komunikacyjnych. Na przykład, protokół USB (Universal Serial Bus) jest powszechnie stosowany do komunikacji z wieloma różnymi urządzeniami, takimi jak klawiatury, myszki, drukarki, czy dyski zewnętrzne. Inne popularne protokoły to HDMI (High Definition Multimedia Interface) do transmisji wideo i dźwięku oraz Ethernet do połączeń sieciowych.

Dzięki współpracy komputera z urządzeniami wejścia/wyjścia możliwe jest interaktywne korzystanie z komputera oraz przetwarzanie i wyświetlanie danych w różnych formach. Ten proces jest kluczowy dla funkcjonowania każdego systemu komputerowego i umożliwia użytkownikom wykonywanie różnorodnych zadań i operacji.

## Proszę opisać czym jest SOLID  w programowaniu obiektowym?

SOLID to zbiór pięciu zasad programowania obiektowego, które promują projektowanie oprogramowania w sposób elastyczny, skalowalny i łatwy w utrzymaniu. Oto krótkie opisy każdej z tych zasad:

1. **Single Responsibility Principle (SRP) - Zasada pojedynczej odpowiedzialności:**
   - Zasada ta mówi, że każda klasa powinna mieć tylko jedną odpowiedzialność i być odpowiedzialna za jedną, dobrze zdefiniowaną część funkcjonalności. Oznacza to, że klasa powinna być zmieniana tylko wtedy, gdy zmienia się jedno logiczne aspekt programu. Dzięki temu łatwiej jest zrozumieć, testować i utrzymywać kod.

2. **Open/Closed Principle (OCP) - Zasada otwarte/zamknięte:**
   - Zasada ta mówi, że klasy powinny być otwarte na rozszerzenie (open for extension) i zamknięte na modyfikację (closed for modification). Oznacza to, że istniejące zachowanie klasy nie powinno być zmieniane, ale powinno być możliwe dodawanie nowych funkcji poprzez dziedziczenie i implementację interfejsów.

3. **Liskov Substitution Principle (LSP) - Zasada zastępowalności Liskov:**
   - Zasada ta mówi, że obiekty powinny być zastępowalne przez ich podtypy bez wpływu na poprawność działania programu. Oznacza to, że jeśli klasa A jest podtypem klasy B, to można używać obiektów klasy A wszędzie, gdzie oczekiwany jest obiekt klasy B, i program powinien zachowywać się poprawnie.

4. **Interface Segregation Principle (ISP) - Zasada segregacji interfejsów:**
   - Zasada ta mówi, że interfejsy powinny być cienkie i specyficzne dla potrzeb klientów, aby uniknąć sytuacji, w której klienty zmusza się do implementacji metod, których nie potrzebują. Oznacza to, że lepiej jest tworzyć wiele mniejszych interfejsów, które są odpowiedzialne za konkretne aspekty funkcjonalności.

5. **Dependency Inversion Principle (DIP) - Zasada odwrócenia zależności:**
   - Zasada ta mówi, że klasy powinny być oparte na abstrakcjach, a nie na konkretnych implementacjach. Oznacza to, że moduły wysokopoziomowe nie powinny zależeć od modułów niskopoziomowych, ale oba rodzaje modułów powinny zależeć od abstrakcji. Dzięki temu łatwiej jest wprowadzać zmiany i testować kod.

SOLID to zbiór zasad projektowania oprogramowania, które pomagają tworzyć bardziej elastyczne, skalowalne i łatwe w utrzymaniu systemy, poprzez promowanie dobrej praktyki projektowej i unikanie pułapek, które mogą prowadzić do złej jakości kodu i trudności w jego rozwijaniu.

## Proszę opisać protokół TCP/IP - podać jego model warstwowy.

Protokół TCP/IP (Transmission Control Protocol/Internet Protocol) jest zestawem standardów komunikacyjnych używanych do przesyłania danych w sieciach komputerowych. Protokół ten obejmuje wiele warstw, które są zorganizowane w modelu warstwowym. Oto opis modelu warstwowego TCP/IP:

1. **Warstwa dostępu do sieci (ang. Network Access Layer):**
   - Ta warstwa jest najbliższa sprzętowi fizycznemu i obejmuje protokoły, które obsługują przesyłanie danych na konkretnym medium transmisyjnym, takim jak Ethernet, Wi-Fi czy token ring. Tutaj definiowane są również reguły adresowania fizycznego, np. adresy MAC.

2. **Warstwa internetowa (ang. Internet Layer):**
   - Warstwa ta obsługuje routowanie danych pomiędzy różnymi sieciami oraz zapewnia adresację IP, która umożliwia identyfikację i adresowanie urządzeń w sieci. Najważniejszym protokołem w tej warstwie jest protokół IP (Internet Protocol), który jest odpowiedzialny za przesyłanie pakietów danych między różnymi hostami w sieci.

3. **Warstwa transportowa (ang. Transport Layer):**
   - Warstwa ta zapewnia niezawodne, zorientowane na połączenie przesyłanie danych między aplikacjami działającymi na różnych urządzeniach. Najczęściej używanymi protokołami w tej warstwie są Transmission Control Protocol (TCP) oraz User Datagram Protocol (UDP). TCP zapewnia niezawodne, strumieniowe przesyłanie danych z mechanizmem kontroli przepływu i mechanizmem odtwarzania, podczas gdy UDP zapewnia przesyłanie danych bez potwierdzeń odbioru, co jest bardziej efektywne w niektórych przypadkach, ale mniej niezawodne.

4. **Warstwa aplikacyjna (ang. Application Layer):**
   - Warstwa ta zawiera aplikacje i protokoły używane przez użytkowników końcowych, takie jak przeglądarki internetowe, klienty poczty elektronicznej, czy klienty FTP (File Transfer Protocol). Protokoły w tej warstwie obejmują HTTP, FTP, SMTP, POP3, IMAP, DNS i wiele innych.

Model warstwowy TCP/IP jest stosowany w praktyce do organizacji różnych protokołów komunikacyjnych w sposób hierarchiczny, co ułatwia projektowanie, zarządzanie i rozwijanie sieci komputerowych oraz umożliwia komunikację między różnymi urządzeniami i aplikacjami w sieci internetowej.

![](https://egzamin-e13.pl/wp-content/uploads/2015/11/model-sieci.png)

## Polityka bezpieczeństwa informatycznego i jej elementy.

Polityka bezpieczeństwa informatycznego to zbiór wytycznych, procedur, reguł i praktyk mających na celu zapewnienie ochrony danych, systemów informatycznych oraz infrastruktury IT przed zagrożeniami i atakami. Obejmuje ona szereg elementów, które mają na celu zdefiniowanie, wdrożenie i utrzymanie odpowiednich zabezpieczeń w organizacji. Oto główne elementy polityki bezpieczeństwa informatycznego:

1. **Cel i zakres:**
   - Określenie ogólnego celu polityki bezpieczeństwa informatycznego oraz zakresu jej stosowania, czyli do jakich systemów, danych i zasobów IT ma być stosowana.

2. **Zasady i wytyczne:**
   - Zdefiniowanie podstawowych zasad, z którymi powinny być zgodne wszystkie działania i decyzje dotyczące bezpieczeństwa informatycznego. Wskazówki i wytyczne mogą obejmować kwestie takie jak dostęp do danych, hasła, bezpieczeństwo fizyczne, zarządzanie ryzykiem, audyt bezpieczeństwa itp.

3. **Rola i odpowiedzialność:**
   - Określenie ról i odpowiedzialności pracowników w zakresie bezpieczeństwa informatycznego. To obejmuje zarządzanie dostępem do systemów i danych, monitorowanie zdarzeń bezpieczeństwa, reagowanie na incydenty, audytowanie, szkolenia itp.

4. **Zarządzanie dostępem:**
   - Określenie zasad i procedur dotyczących nadawania, zarządzania i usuwania uprawnień dostępu do systemów i danych, w tym zasady dotyczące haseł, kont użytkowników, kontroli dostępu fizycznego itp.

5. **Ochrona danych:**
   - Określenie środków technicznych i organizacyjnych służących do ochrony danych, w tym szyfrowania, tworzenia kopii zapasowych, monitorowania ruchu sieciowego, zarządzania danymi osobowymi, zasad usuwania danych itp.

6. **Zarządzanie incydentami bezpieczeństwa:**
   - Określenie procedur reagowania na incydenty bezpieczeństwa, w tym raportowania, analizy, przeciwdziałania oraz przywracania normalnego funkcjonowania systemów po ataku lub awarii.

7. **Szkolenia i świadomość:**
   - Zapewnienie regularnych szkoleń i świadomości pracowników w zakresie zagrożeń bezpieczeństwa informatycznego oraz zasad postępowania w przypadku podejrzenia ataku lub incydentu.

8. **Audyt i monitorowanie:**
   - Określenie procedur audytu bezpieczeństwa informatycznego oraz monitorowania systemów i sieci w celu wykrywania nieprawidłowości, ataków lub nieautoryzowanego dostępu.

9. **Aktualizacje i utrzymanie:**
   - Zapewnienie regularnych aktualizacji oprogramowania, łatek bezpieczeństwa oraz przeglądów zabezpieczeń w celu utrzymania infrastruktury IT w najwyższej możliwej formie bezpieczeństwa.

Polityka bezpieczeństwa informatycznego stanowi fundament dla skutecznej ochrony systemów informatycznych i danych w organizacji. Jej skuteczne wdrożenie wymaga zaangażowania wszystkich pracowników oraz ciągłego monitorowania i aktualizowania zabezpieczeń zgodnie z dynamicznym środowiskiem cyberzagrożeń.

## Procedury sterujące przepływem programu

Procedury sterujące przepływem programu to instrukcje, które decydują o kolejności wykonywania się operacji w programie. W językach programowania istnieje kilka podstawowych procedur sterujących przepływem programu:

1. **Instrukcje warunkowe (if, else if, else):**
   - Instrukcje warunkowe pozwalają na wykonywanie określonych bloków kodu w zależności od spełnienia określonego warunku. Na przykład:
     ```
     if (warunek) {
         // kod do wykonania, jeśli warunek jest spełniony
     } else {
         // kod do wykonania, jeśli warunek nie jest spełniony
     }
     ```

2. **Pętle (for, while, do-while):**
   - Pętle pozwalają na wielokrotne wykonanie tego samego bloku kodu. Różnią się od siebie sposobem sprawdzania warunku i momentem wykonania. Na przykład:
     ```
     for (inicjalizacja; warunek; inkrementacja) {
         // kod do wykonania
     }

     while (warunek) {
         // kod do wykonania
     }

     do {
         // kod do wykonania
     } while (warunek);
     ```

3. **Instrukcje skoku (break, continue, return):**
   - Instrukcje skoku pozwalają na zmianę standardowego przepływu programu. Na przykład:
     - Instrukcja `break` kończy działanie pętli lub instrukcji switch.
     - Instrukcja `continue` przechodzi do następnego obiegu pętli, pomijając pozostałe instrukcje w obecnym obiegu.
     - Instrukcja `return` powoduje zakończenie działania funkcji i zwrócenie wartości.

4. **Instrukcje switch-case:**
   - Instrukcje switch-case pozwalają na wybór jednej z wielu możliwych ścieżek wykonania w zależności od wartości wyrażenia sterującego. Na przykład:
     ```
     switch (wyrażenie) {
         case wartość1:
             // kod do wykonania
             break;
         case wartość2:
             // kod do wykonania
             break;
         default:
             // kod do wykonania, gdy żadna z powyższych wartości nie pasuje
     }
     ```

Procedury sterujące przepływem programu są kluczowymi elementami struktury programu, pozwalającymi na elastyczne zarządzanie jego wykonaniem i odpowiednie reakcje na różne sytuacje. Poprawne użycie tych procedur pomaga w tworzeniu czytelnych, efektywnych i funkcjonalnych programów.


# LUB

Procedury sterujące przepływem programu, znane również jako instrukcje sterujące, są kluczowym elementem każdego języka programowania. Pozwalają one na kontrolowanie kolejności wykonywania instrukcji w programie. Oto kilka podstawowych typów instrukcji sterujących:

1. **Kontynuacja od innego punktu programu (skok)**: Pozwala na przeniesienie kontroli do innej części programu³.
2. **Warunkowe wykonanie grupy wyrażeń (wybór)**: Pozwala na wykonanie różnych instrukcji w zależności od spełnienia określonego warunku³.
3. **Powtarzanie wykonywania grupy wyrażeń (pętla)**: Pozwala na wielokrotne wykonanie tej samej grupy instrukcji³.
4. **Wykonywanie grupy odległych wyrażeń, po których sterowanie powraca do miejsca wywołania (podprogram, procedura)**: Pozwala na wywołanie grupy instrukcji zdefiniowanych w innym miejscu programu³.
5. **Zupełne przerwanie wykonywania programu**: Pozwala na natychmiastowe zakończenie działania programu³.

Rodzaje instrukcji sterujących mogą się różnić w zależności od języka programowania, ale mimo to mogą być pogrupowane ze względu na efekt, jaki powodują³.


## Zadania administratora systemu baz danych.

Administrator systemu baz danych (DBA - Database Administrator) ma wiele zadań i obowiązków związanych z zarządzaniem, utrzymaniem i optymalizacją systemów baz danych. Oto niektóre z głównych zadań administratora systemu baz danych:

1. **Instalacja i konfiguracja systemu baz danych:**
   - Administrator jest odpowiedzialny za instalację i konfigurację systemu zarządzania bazą danych (DBMS) na serwerach. Należy do tego wybór odpowiedniej wersji DBMS, instalacja oprogramowania, konfiguracja parametrów systemowych i zapewnienie zgodności z wymaganiami aplikacji.

2. **Utrzymywanie i monitorowanie wydajności systemu:**
   - Administrator dba o wydajność systemu baz danych poprzez monitorowanie zużycia zasobów, identyfikowanie i optymalizowanie zapytań, zarządzanie przestrzenią dyskową, analizowanie i usuwanie błędów wydajnościowych oraz planowanie skalowania systemu w przypadku wzrostu obciążenia.

3. **Zarządzanie bezpieczeństwem:**
   - Administracja bezpieczeństwem obejmuje nadawanie uprawnień dostępu do danych użytkownikom, tworzenie ról i profili bezpieczeństwa, monitorowanie aktywności użytkowników, wdrażanie procedur audytowych i zapewnienie zgodności z regulacjami dotyczącymi ochrony danych.

4. **Tworzenie kopii zapasowych i przywracanie danych:**
   - Administrator jest odpowiedzialny za regularne tworzenie kopii zapasowych danych w celu zapewnienia ochrony przed utratą danych w przypadku awarii systemu, błędów użytkowników lub ataków. Ponadto musi być w stanie skutecznie przywrócić dane z kopii zapasowych w razie potrzeby.

5. **Optymalizacja i tunelowanie baz danych:**
   - Administrator jest odpowiedzialny za optymalizację struktury baz danych, indeksów i zapytań w celu zapewnienia efektywnego wykorzystania zasobów systemu oraz szybkiego dostępu do danych. Może również przeprowadzać tunelowanie bazy danych w celu dostosowania jej do zmieniających się potrzeb i wymagań aplikacji.

6. **Wsparcie techniczne i rozwiązywanie problemów:**
   - Administrator zapewnia wsparcie techniczne dla użytkowników i deweloperów, pomagając w diagnozowaniu i rozwiązywaniu problemów związanych z bazą danych, wydajnością zapytań, dostępem do danych, konfiguracją aplikacji itp.

7. **Aktualizacje i migracje:**
   - Administrator jest odpowiedzialny za śledzenie nowych wersji oprogramowania DBMS, planowanie i przeprowadzanie aktualizacji systemu oraz migracji danych między różnymi wersjami lub rodzajami systemów baz danych.

8. **Dokumentacja i szkolenia:**
   - Administrator dba o dokumentację konfiguracji, procedur i zasad zarządzania bazą danych, a także zapewnia szkolenia dla użytkowników i personelu IT w zakresie korzystania z systemu baz danych oraz procedur bezpieczeństwa i wydajności.

Zadania administratora systemu baz danych są kluczowe dla zapewnienia niezawodności, wydajności, bezpieczeństwa i zgodności systemu baz danych z wymaganiami biznesowymi i regulacyjnymi organizacji. Dzięki odpowiedniemu zarządzaniu, system bazy danych może efektywnie wspierać działalność firmy i zapewnić bezpieczne przechowywanie i dostęp do danych.

## Proszę opisać na czym polega pakowanie danych. Podać przykład algorytmów

Pakowanie danych (ang. data compression) to proces redukcji rozmiaru danych poprzez zastosowanie różnych technik i algorytmów. Celem pakowania danych jest zmniejszenie ilości przestrzeni dyskowej lub przepustowości sieci potrzebnej do przechowywania lub przesyłania danych, co może przynieść korzyści w zakresie efektywności, oszczędności zasobów i szybkości przetwarzania.

Istnieją dwa główne rodzaje pakowania danych:

1. **Pakowanie bezstratne (ang. lossless compression):** W tym rodzaju pakowania danych nie tracimy żadnych informacji podczas procesu kompresji i dekompresji. Dane można dokładnie przywrócić do swojego pierwotnego stanu. Przykłady algorytmów pakowania bezstratnego obejmują:
   - Algorytm LZ77 i LZ78
   - Algorytm Huffmana
   - Algorytm Lempela-Ziv-Welch (LZW)
   - Algorytm Deflate (używany w formacie ZIP)
   - Algorytm Burrowsa-Wheelera (BWT)

2. **Pakowanie stratne (ang. lossy compression):** W tym przypadku niektóre informacje są tracone podczas procesu kompresji, co prowadzi do mniejszego rozmiaru danych, ale nie można dokładnie przywrócić oryginalnych danych. Pakowanie stratne jest często stosowane w przypadku multimediów, takich jak obrazy, dźwięki lub wideo. Przykłady algorytmów pakowania stratnego obejmują:
   - Algorytm JPEG (dla obrazów)
   - Algorytm MP3 (dla dźwięku)
   - Algorytm MPEG (dla wideo)

Algorytmy pakowania danych różnią się pod względem skuteczności, szybkości i stopnia kompresji, co oznacza, że nie ma jednego uniwersalnego algorytmu, który byłby idealny dla wszystkich rodzajów danych. Wybór odpowiedniego algorytmu zależy od rodzaju danych, które chcemy kompresować, oraz wymagań co do szybkości i efektywności kompresji.

## Czym jest JSON i do czego jest używany?
JSON (JavaScript Object Notation) to lekki format danych, który jest popularnie używany do przechowywania i przesyłania strukturalnych danych między różnymi aplikacjami. Jest to tekstowy format danych, który jest czytelny dla ludzi i łatwy do parsowania dla maszyn.

JSON składa się z par klucz-wartość, gdzie klucze są ciągami znaków (tekstowymi) i wartościami mogą być liczby, ciągi znaków, logiczne wartości (true/false), tablice, obiekty JSON lub null. Oto przykład prostego obiektu JSON:

```json
{
  "imie": "Jan",
  "nazwisko": "Kowalski",
  "wiek": 30,
  "zatrudniony": true,
  "adres": {
    "ulica": "Kwiatowa",
    "numer": "123",
    "miasto": "Warszawa"
  },
  "hobby": ["sport", "muzyka", "podróże"]
}
```

JSON jest szeroko używany w programowaniu webowym do przesyłania danych między klientem a serwerem w formacie, który jest łatwy do przetwarzania przez przeglądarkę internetową oraz serwer HTTP. Jest to również popularny format do przechowywania konfiguracji, danych konfiguracyjnych, danych API, dzienników (logów) i innych rodzajów danych w aplikacjach webowych i mobilnych.

Główne cechy JSON to jego prostota, czytelność dla człowieka, łatwość parsowania i generowania przez różne języki programowania oraz wsparcie przez wiele narzędzi i bibliotek. Dlatego JSON jest powszechnie stosowany w dziedzinie programowania webowego i aplikacji klient-serwer.

## Opisz czym jest ORM, Podaj przykłady zastosowania.
ORM (Object-Relational Mapping) to technika programistyczna, która umożliwia mapowanie obiektów z języków programowania obiektowego (takich jak Java, Python, C#) na struktury danych w relacyjnych bazach danych, oraz odwrotnie, czyli mapowanie danych z baz danych na obiekty w kodzie programu.

Głównym celem ORM jest ułatwienie programistom korzystania z baz danych poprzez reprezentację danych w sposób obiektowy, co pozwala na bardziej intuicyjne operowanie na danych oraz zminimalizowanie potrzeby pisania zapytań SQL.

Przykłady zastosowania ORM:

1. **Aplikacje webowe:**
   - W aplikacjach webowych ORM może być wykorzystywane do mapowania danych z bazy danych (np. MySQL, PostgreSQL) na obiekty w kodzie serwera (np. Java z frameworkiem Spring, Python z frameworkiem Django), co ułatwia interakcję z bazą danych i operacje CRUD (Create, Read, Update, Delete).

2. **Aplikacje mobilne:**
   - W aplikacjach mobilnych ORM może być używane do pracy z lokalnymi bazami danych na urządzeniach mobilnych (np. SQLite w Androidzie, CoreData w iOS), co umożliwia efektywne zarządzanie danymi w aplikacji.

3. **Testowanie:**
   - ORM ułatwia testowanie aplikacji poprzez dostarczenie warstwy abstrakcji między kodem aplikacji a bazą danych. Dzięki temu można łatwo zaimplementować testy jednostkowe, integracyjne i funkcjonalne, które wykorzystują obiekty zamiast rzeczywistych danych z bazy danych.

4. **Raportowanie i analiza danych:**
   - ORM umożliwia tworzenie złożonych zapytań do bazy danych i przetwarzanie wyników w formie obiektów, co ułatwia generowanie raportów, analizę danych i wizualizację danych w aplikacjach biznesowych.

5. **Skalowalność i przenośność:**
   - ORM zapewnia wysoki poziom abstrakcji nad bazą danych, co ułatwia przenoszenie aplikacji między różnymi platformami i bazami danych, oraz skalowanie aplikacji poprzez zmianę bazy danych bez konieczności zmiany kodu aplikacji.

Przykłady popularnych frameworków ORM to Hibernate dla języka Java, Entity Framework dla języka C#, SQLAlchemy dla języka Python, ActiveRecord dla języka Ruby. Te frameworki oferują bogate funkcjonalności ORM i są powszechnie stosowane w tworzeniu aplikacji webowych i mobilnych.

## Podaj definicję rekurencji oraz przykłady zastosowania

Rekurencja to technika programistyczna, w której funkcja wywołuje samą siebie. Innymi słowy, funkcja rekurencyjna jest funkcją, która odwołuje się do samej siebie w swoim ciele, zwykle w celu rozwiązania problemu, który może być podzielony na mniejsze, podobne podproblemy.

Definicja rekurencji:
Rekurencja jest techniką programistyczną, w której funkcja odwołuje się do samej siebie w swoim ciele.

Przykłady zastosowania rekurencji:

1. **Obliczanie silni:**
   - Silnia liczby n, oznaczana jako n!, to iloczyn wszystkich liczb całkowitych od 1 do n. Silnię można obliczyć rekurencyjnie, korzystając z definicji n! = n * (n-1)!, przy czym wartość 0! jest równa 1. Przykładowa implementacja w języku Python:
   ```python
   def silnia(n):
       if n == 0:
           return 1
       else:
           return n * silnia(n-1)
   ```

2. **Fibonacci sequence:**
   - Ciąg Fibonacciego to ciąg liczb, w którym każda liczba to suma dwóch poprzednich liczb. Rekurencyjna funkcja może być użyta do obliczenia n-tego wyrazu ciągu Fibonacciego. Przykładowa implementacja w języku Python:
   ```python
   def fibonacci(n):
       if n <= 1:
           return n
       else:
           return fibonacci(n-1) + fibonacci(n-2)
   ```

3. **Przechodzenie drzewa binarnego:**
   - Rekurencja jest często stosowana w przechodzeniu drzewa binarnego, gdzie każdy węzeł ma lewego i prawego potomka. Przykładowe operacje, które mogą być wykonane rekurencyjnie na drzewie binarnym, to np. przeszukiwanie inorder, preorder lub postorder.

4. **Sortowanie przez scalanie (Merge sort):**
   - Algorytm sortowania przez scalanie jest rekurencyjnym algorytmem sortowania, który dzieli tablicę na mniejsze części, sortuje każdą z nich, a następnie łączy w celu uzyskania posortowanej tablicy.

5. **Generowanie permutacji:**
   - Rekurencja może być wykorzystana do generowania wszystkich permutacji zbioru danych. Dla przykładu, generowanie permutacji zbioru liczb {1, 2, 3} można zrealizować rekurencyjnie, wykorzystując backtracking.

Rekurencja jest przydatną techniką programistyczną, szczególnie w przypadku problemów, które mogą być łatwo podzielone na mniejsze podproblemy o takiej samej strukturze. Jednakże, należy pamiętać, że nadmierna rekurencja może prowadzić do przepełnienia stosu (stack overflow), dlatego ważne jest odpowiednie zarządzanie rekurencją i warunkami zakończenia.

## Analiza SWOT – definicja i cele jej użycia.

Analiza SWOT jest narzędziem strategicznego planowania wykorzystywanym do oceny sytuacji organizacji poprzez identyfikację jej wewnętrznych mocnych i słabych stron oraz zewnętrznych szans i zagrożeń. Skrót SWOT pochodzi od angielskich słów Strengths (Mocne strony), Weaknesses (Słabe strony), Opportunities (Szanse) i Threats (Zagrożenia).

Definicja:
Analiza SWOT to strukturalny framework do identyfikacji i oceny czynników wewnętrznych i zewnętrznych wpływających na organizację w celu opracowania strategii biznesowej.

Cele użycia analizy SWOT:

1. **Ocena wewnętrznych mocnych i słabych stron organizacji:**
   - Analiza SWOT pomaga zidentyfikować unikalne zdolności, zasoby, umiejętności i aktywa organizacji (mocne strony), a także obszary, w których organizacja może być słaba (słabe strony). To pozwala organizacji na lepsze wykorzystanie swoich mocnych stron oraz identyfikację obszarów do poprawy.

2. **Identyfikacja zewnętrznych szans i zagrożeń:**
   - Analiza SWOT umożliwia organizacji zrozumienie otoczenia zewnętrznego, w tym rynku, konkurencji, trendów branżowych, zmian prawnych czy technologicznych. Pozwala to na wykrycie szans, które organizacja może wykorzystać (szanse), a także na identyfikację czynników zewnętrznych, które mogą stanowić potencjalne zagrożenia dla organizacji (zagrożenia).

3. **Formułowanie strategii biznesowej:**
   - Na podstawie analizy SWOT organizacja może opracować strategie biznesowe, które wykorzystują jej mocne strony do wykorzystania szans, minimalizując jednocześnie wpływ słabych stron i zagrożeń. Analiza SWOT pomaga organizacji zdefiniować cele, priorytety i działania potrzebne do osiągnięcia sukcesu w dynamicznym środowisku biznesowym.

4. **Podnoszenie świadomości i zaangażowania pracowników:**
   - Wykonanie analizy SWOT może również przyczynić się do zwiększenia świadomości pracowników na temat kluczowych czynników wpływających na organizację oraz do zaangażowania ich w proces planowania strategicznego. Pozwala to na lepsze zrozumienie celów i strategii organizacji oraz na zaangażowanie pracowników w realizację tych celów.

Analiza SWOT jest wszechstronnym narzędziem, które może być stosowane przez różne typy organizacji, w tym firmy, instytucje edukacyjne, organizacje non-profit czy agencje rządowe, aby lepiej zrozumieć swoje środowisko i opracować efektywne strategie biznesowe.

## Transakcja w bazie danych, podaj jej cechy.

Transakcja w bazie danych odnosi się do logicznej jednostki operacyjnej, która obejmuje jedną lub więcej operacji bazodanowych, takich jak wstawianie, aktualizacja lub usunięcie danych. Transakcje są wykonywane w sposób atomowy, co oznacza, że entitety bazodanowe przechodzą ze stanu konsystentnego w stan konsystentny, a baza danych pozostaje w spójnym stanie, niezależnie od ewentualnych awarii lub błędów.

Cechy transakcji w bazie danych:

1. **Atomowość (ACID):**
   - Transakcje są atomowe, co oznacza, że są wykonywane jako całość lub wcale. Jeśli jedna część transakcji nie powiedzie się, cała transakcja jest cofana do jej stanu pierwotnego, co zapewnia spójność danych. Zasada ta jest nazywana cechą atomowości.

2. **Spójność (ACID):**
   - Transakcje zapewniają spójność danych, co oznacza, że po zakończeniu transakcji baza danych pozostaje w spójnym stanie, spełniając określone reguły integralności danych.

3. **Izolacja (ACID):**
   - Transakcje są izolowane od siebie nawzajem, co oznacza, że jedna transakcja nie może wpływać na wyniki innych transakcji, które są równolegle wykonywane. To zapewnia niezależność transakcji od siebie.

4. **Trwałość (ACID):**
   - Trwałość oznacza, że po zakończeniu transakcji wprowadzone zmiany w bazie danych są trwałe i nie zostaną utracone nawet w przypadku awarii systemu. Dzięki temu zmiany są zapisywane na dysku i pozostają dostępne nawet po ponownym uruchomieniu systemu.

Powyższe cechy transakcji, znane jako ACID (Atomicity, Consistency, Isolation, Durability), stanowią fundament podstawowych właściwości, które są niezbędne dla zachowania integralności danych i spójności baz danych w środowisku wielu równoległych operacji. Wspierają one niezawodne i skuteczne operacje na danych w bazach danych.

## Pojęcie równowagi rynkowej.

Równowaga rynkowa to stan, w którym popyt na dany produkt lub usługę jest równy podaży tego produktu lub usługi. Oznacza to, że na rynku nie ma nadwyżki ani niedoboru towarów czy usług, co prowadzi do stabilności cen i ilości na rynku.

Główne cechy równowagi rynkowej to:

1. **Równowaga cenowa:** W równowadze rynkowej cena produktu lub usługi ustala się na poziomie, który skutecznie równoważy popyt i podaż. Cena ta jest nazywana ceną równowagi.

2. **Równowaga ilościowa:** W równowadze rynkowej ilość produktów lub usług, które są chętnie oferowane przez producentów, jest równa ilością, które są chętnie nabywane przez konsumentów.

3. **Brak nadwyżki ani niedoboru:** W równowadze rynkowej nie ma nadwyżki (nadmiaru) ani niedoboru (braku) produktów czy usług na rynku. Producenci dostarczają dokładnie tyle towarów, ile klienci chcą kupić.

Równowaga rynkowa jest kluczowym pojęciem w teorii ekonomii, ponieważ stanowi fundament analizy funkcjonowania rynków oraz mechanizmów, które wpływają na cenę i ilość dóbr na rynku. Jednakże, w praktyce równowaga rynkowa może być zakłócana przez różne czynniki, takie jak interwencje rządowe, zmiany w preferencjach konsumentów, czy działania konkurencji, co może prowadzić do zmian w cenach i ilościach na rynku.

## Różnice między podażą a popytem.

1. **Definicja:**
   - **Popyt:** Odnosi się do ilości towarów lub usług, które klienci są chętni kupić przy określonej cenie w danym czasie.
   - **Podaż:** Odnosi się do ilości towarów lub usług, które producenci są gotowi dostarczyć na rynek przy określonej cenie w danym czasie.