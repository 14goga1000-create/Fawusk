# CustomAV Faw Edition — обязательно прочитать перед внедрением

## Что это

Это новая ветка CustomAV 0.5, заточенная под Fawuks: безопасное чтение контейнеров, проверка ZIP и подключаемый reader для собственного формата `.faw`.

Старая универсальная версия сохранена в `base_v05/` и не изменяется.

## Архитектура

```text
Fawuks archive reader (.faw/.zip)
        ↓ entries + streams
CustomAV Faw Edition policy
        ↓
CustomAV 0.5 signature/static scanner
        ↓
clean / review / blocked / incomplete
```

## Важное ограничение `.faw`

Формат `.faw` закрытый и его спецификация не входит в этот пакет. Поэтому не нужно притворяться, что scanner умеет угадывать его структуру. В Go добавляется `FawReader`-адаптер: сам Fawuks отдаёт scanner безопасный список entry и `io.ReadCloser` для содержимого.

Когда формат `.faw` стабилизируется, можно заменить adapter на настоящий parser, не меняя policy и сигнатурный слой.

## Что поддерживается сейчас

- ZIP — нативная проверка через `archive/zip`;
- `.faw` — через adapter API Fawuks;
- RAR намеренно не поддерживается;
- path traversal, абсолютные пути, symlink/hardlink, лимиты размера и количества entry;
- encrypted entry — статус `incomplete`, пока Fawuks не передал пароль через callback;
- EICAR и расширяемая база сигнатур;
- ZIP/JAR вложенность через stream scanner.

## Подключение

Используй пакет `go/fawsecurity`:

```go
scanner := fawsecurity.NewScanner(fawsecurity.Config{
    EntryScanner: customav.FawEntryScanner{Client: customavClient},
    MaxEntries: 10000,
    MaxUnpackedBytes: 1_000_000_000,
})

report, err := scanner.ScanFAW(ctx, fawReader)
```

Для ZIP:

```go
report, err := scanner.ScanZIP(ctx, zipPath)
```

`FawReader` должен выдавать entry с именем, размером, флагом encryption и функцией открытия потока. Scanner не должен сам выполнять содержимое.

## Политика

- malware / path traversal / archive bomb → `blocked`;
- `TEST SIGNATURE DETECTED` → тестовый детект, не настоящий вирус;
- modified / untrusted → `review`;
- encrypted или нечитабельный entry → `incomplete`, не зелёный результат;
- зелёный `clean` только после проверки всех доступных entry.

## Шифрование

`crypto.go` защищает карантин и приватные JSON-отчёты через AES-256-GCM и парольную деривацию PBKDF2-HMAC-SHA256. Это не заменяет шифрование самого `.faw`: формат архива должен отдельно определить encrypted entry, KDF, nonce, authentication tag и recovery policy.

Не хранить пароль в конфиге, логах или отчёте. Не использовать один nonce повторно.

## Запреты

- не использовать shell при запуске scanner;
- не распаковывать до проверки путей и лимитов;
- не следовать links;
- не удалять оригинал автоматически;
- не отправлять содержимое наружу без согласия;
- не разрешать ИИ отменять `blocked` без явной пользовательской политики.

## Тесты перед публикацией

Обязательно проверить:

1. обычный ZIP;
2. ZIP с EICAR;
3. ZIP с `../escape.txt`;
4. ZIP bomb / превышение размера;
5. encrypted ZIP;
6. `.faw` с обычным entry;
7. `.faw` с повреждённой таблицей;
8. `.faw` с encrypted entry без пароля;
9. вложенный ZIP/JAR;
10. отмену контекста во время чтения.

## Распространение и лицензия

Исходный код CustomAV Faw Edition распространяется по лицензии MIT из файла `LICENSE`. Fawusk Contributors могут включать, изменять и распространять этот код вместе с Fawuks при сохранении уведомления об авторских правах и текста лицензии. Это разрешение не меняет лицензию исходного кода Fawuks и не передаёт права на формат `.faw` или бренды Fawusk.
