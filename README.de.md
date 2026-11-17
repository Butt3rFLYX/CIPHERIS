<p align="center"><img src="packaging/brand/logo.svg" width="96" alt="CIPHERIS Logo"></p>

<h1 align="center">CIPHERIS</h1>

<p align="center">Verschlüsselte Nachrichten, versteckt in Bildern. Offline, auf deinem eigenen Computer.</p>

<p align="center"><a href="README.md">English</a> · <b>Deutsch</b> · <a href="README.tr.md">Türkçe</a></p>

CIPHERIS verschlüsselt eine Textnachricht und versteckt sie in einem Bild. Das Bild sieht aus wie vorher; nur wer den erzeugten Schlüssel hat, kann die Nachricht wieder lesen. Alles läuft lokal: kein Konto, keine Cloud, kein Internet.

## Installieren

**Download (empfohlen):** Lade die Datei für dein System unter [Releases](../../releases) herunter.

| System | Datei | Erster Start |
| --- | --- | --- |
| macOS (Apple Silicon und Intel) | `CIPHERIS-macOS.zip` | entpacken, `CIPHERIS.app` in den Ordner *Programme* ziehen, einmal öffnen (siehe unten) |
| Windows | `CIPHERIS-Windows.zip` | entpacken, `CIPHERIS.exe` doppelklicken; wenn Windows warnt: *Weitere Informationen*, dann *Trotzdem ausführen* |
| Linux | `CIPHERIS-Linux.tar.gz` | entpacken und `./cipheris` starten |

**Erster Start auf macOS.** Die App ist nicht von Apple beglaubigt, deshalb blockiert macOS den ersten Start. Ab macOS 15: einmal versuchen, sie zu öffnen, dann *Systemeinstellungen* → *Datenschutz & Sicherheit* → nach unten scrollen → *Trotzdem öffnen*. Auf älteren Versionen: Rechtsklick auf die App → *Öffnen*. Das ist nur einmal nötig.

Jeder Release enthält Prüfsummen in `SHA256SUMS.txt`. Prüfe deinen Download vor dem ersten Start mit `shasum -a 256 <Datei>` (macOS, Linux) oder `Get-FileHash <Datei>` (Windows). Die Apps sind nicht mit einem kostenpflichtigen Apple- oder Microsoft-Zertifikat signiert, deshalb erscheint beim ersten Start eine Warnung.

**Selbst bauen:** siehe [englisches README](README.md#install).

Auf macOS und Windows öffnet sich CIPHERIS in einem eigenen Fenster, auf Linux im Browser. In beiden Fällen spricht es nur mit deinem eigenen Computer. Im Fenster landen gespeicherte Bilder im Ordner *Downloads*, der sich danach öffnet. Unter Windows nutzt das Fenster Microsoft Edge WebView2, das in Windows 10 und 11 enthalten ist; fehlt es, öffnet sich CIPHERIS stattdessen im Browser. Die Oberfläche gibt es auf Deutsch, Türkisch und Englisch; sie folgt der Sprache deines Systems und lässt sich oben rechts umschalten (DE, TR, EN). CIPHERIS beendet sich mit *beenden* oder von selbst wenige Minuten, nachdem du den Tab geschlossen hast.

## Benutzen

**Nachricht verstecken**

1. Ein Bild in das Feld *bild* ziehen. Fotos (JPEG, HEIC und andere) werden in PNG umgewandelt.
2. Die Nachricht eingeben. Die Anzeige zeigt, wie viel vom Bild sie belegt.
3. *nachricht verstecken* drücken, dann *bild speichern* und den Schlüssel kopieren.

**Nachricht lesen**

1. Zu *auslesen* wechseln und die PNG-Datei hineinziehen, die CIPHERIS erstellt hat.
2. Den Schlüssel eintippen oder einfügen. Groß- und Kleinschreibung, Leerzeichen und Bindestriche spielen keine Rolle, Tippfehler werden erkannt.
3. *nachricht auslesen* drücken.

**Wichtig**

* Ohne den Schlüssel ist die Nachricht verloren. Es gibt keine Wiederherstellung.
* Bild und Schlüssel über verschiedene Wege verschicken.
* Das Bild als **Datei** verschicken (Mail-Anhang, AirDrop, USB-Stick, Cloud-Link). Messenger und soziale Netzwerke komprimieren Bilder und zerstören dabei die Nachricht.
* Jedes Bild nur einmal verwenden und das Original nicht neben dem neuen Bild teilen.
* Im Browser (Linux) können Erweiterungen, die jede Seite lesen dürfen, auch CIPHERIS lesen. Für vertrauliche Nachrichten ein Browser-Profil ohne Erweiterungen nutzen. Das App-Fenster auf macOS und Windows hat keine Erweiterungen.

## Was CIPHERIS schützt, und was nicht

| Eigenschaft | Status |
| --- | --- |
| Ohne Schlüssel ist die Nachricht unlesbar | Ja. Argon2id und XChaCha20 Poly1305, für jede Nachricht ein neuer zufälliger 128-Bit-Schlüssel. |
| Ein verändertes oder beschädigtes Bild wird erkannt | Ja. Jede Änderung führt zu „Keine Nachricht gefunden“, nie zu falschem Text. |
| Ohne Schlüssel gibt es keine Markierung zum Finden | Ja. Die Positionen hängen vom Schlüssel ab. |
| Metadaten des Originals (EXIF, GPS, Kamera) | Werden aus dem neuen Bild entfernt. |
| Niemand kann eine versteckte Nachricht auch nur vermuten | **Nicht garantiert.** Statistische Analyse kann versteckte Daten erkennen, besonders lange Nachrichten in kleinen Bildern. CIPHERIS warnt ab 5 % Belegung. |
| Schutz auf einem Computer mit Schadsoftware | Nein. Siehe [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (Englisch). |

CIPHERIS wurde noch nicht extern auf Sicherheit geprüft. Mehr Details (Englisch): [Sicherheitsrichtlinie](SECURITY.md), [Bedrohungsmodell](docs/THREAT_MODEL.md), [Dateiformat](docs/FORMAT.md).

## Lizenz

MIT, siehe [LICENSE](LICENSE).
