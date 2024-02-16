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