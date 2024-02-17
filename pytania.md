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