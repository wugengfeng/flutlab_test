import 'dart:convert';
import 'dart:typed_data';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:crypto/crypto.dart';
// 假设你还需要其他包来获取配置等

void main() async {
  try {
    final appSecret = await getAppSecret(); // 假设你有一个方法来从安全的地方获取
    final packageName = await getPackageName(); // 假设你有一个方法来获取

    final oauthUrl = generateOAuthURL(appSecret, packageName);
    print('------------------------------------------');
    print(oauthUrl);
    print('------------------------------------------');

    // 可以考虑在此处添加一个方法来在应用的WebView或默认浏览器中打开URL
  } catch (e) {
    print('An error occurred: $e');
  }
}

Future<String> getAppSecret() async {
  // 从配置文件或其他安全地方获取appSecret
  return "hva9QENtxQFreOQvgEl2EkN2";
}

Future<String> getPackageName() async {
  // 从配置文件或其他方法获取包名
  return "com.awesomeproject0673";
}

String generateOAuthURL(String appSecret, String packageName) {
  final thingsboardOAuth2CallbackUrlScheme = "com.awesomeproject0673.app.auth";
  final thingsBoardApiEndpoint = "https://testiot.hulkman.com";
  final oauth2Url =
      "/oauth2/authorization/0e836e10-74ae-11ee-b6ee-e108bd839584";

  final jwt = JWT(
    {'callbackUrlScheme': thingsboardOAuth2CallbackUrlScheme},
    issuer: packageName,
  );
  final key = SecretKey(appSecret);
  final appToken = jwt.sign(key,
      algorithm: _HMACBase64Algorithm.HS512, expiresIn: Duration(minutes: 2));

  var url = Uri.parse(thingsBoardApiEndpoint + oauth2Url);
  final params = Map<String, String>.from(url.queryParameters);
  params['pkg'] = packageName;
  params['appToken'] = appToken;

  return url.replace(queryParameters: params).toString();
}

class _HMACBase64Algorithm extends JWTAlgorithm {
  static const HS512 = _HMACBase64Algorithm('HS512');

  final String _name;

  const _HMACBase64Algorithm(this._name);

  @override
  String get name => _name;

  @override
  Uint8List sign(JWTKey key, Uint8List body) {
    assert(key is SecretKey, 'key must be a SecretKey');
    final secretKey = key as SecretKey;

    final hmac = Hmac(_getHash(name), base64Decode(secretKey.key));

    return Uint8List.fromList(hmac.convert(body).bytes);
  }

  @override
  bool verify(JWTKey key, Uint8List body, Uint8List signature) {
    assert(key is SecretKey, 'key must be a SecretKey');

    final actual = sign(key, body);

    if (actual.length != signature.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] != signature[i]) return false;
    }

    return true;
  }

  Hash _getHash(String name) {
    switch (name) {
      case 'HS256':
        return sha256;
      case 'HS384':
        return sha384;
      case 'HS512':
        return sha512;
      default:
        throw ArgumentError.value(name, 'name', 'unknown hash name');
    }
  }
}
