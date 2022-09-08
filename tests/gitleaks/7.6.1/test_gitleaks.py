"""
How to use these tests:

For mosts cases you should only have to edit the two data structures at the
top of the file here.

(Sometimes it is just as important to test what you are NOT matching against
as it is to test what you are matching against)

SHOULD_MATCH

Add an item to should match if should match. Use the format of the other
entries as a reference.

Fields:

"description" - the rule description that it's matching against
"example" - an example of the leak line
"offender" - what should be matched
"comment" - (optional) rational on why it's there
"filename" - (optional) if the rule matches a specific filename

SHOULD_NOT_MATCH

These items will also be added to the file but should not turn up in the
results

"example" - an example of the leak line
"comment" - (optional) rational on why it's there
"filename" - (optional) if the rule matches a specific filename
"""
import json
import subprocess
import shutil

from pathlib import Path
from unittest import TestCase

SHOULD_MATCH = [
    {
        "description": "General Secret",
        "example": "secret='aOObST8cGSeh3cYNvEGXEXY9BShQx1EtRdfZ=${asdfae}'",
        "offender": "secret='aOObST8cGSeh3cYNvEGXEXY9BShQx1EtRdfZ=${asdfae}'",
        "comment": "Even though this looks like it has a variable at the end, it still has a secret contained in it",
    },
    {
        "description": "Google API Key",
        "example": "Some google key yo AIzaOObST8cGSeh3cYNvEGXEXY9BShQx1EtRdfZ yep here it be!",
        "offender": "AIzaOObST8cGSeh3cYNvEGXEXY9BShQx1EtRdfZ ",
        "comment": "Should capture Google API keys",
    },
    {
        "description": "Mailgun API Key",
        "example": "Mailgun_API_KEY=key-fb959af04c12d5d66091256c2b2076d0",
        "offender": "Mailgun_API_KEY=key-fb959af04c12d5d66091256c2b2076d0",
        "comment": "Should capture Mailgun API keys",
    },
    {
        "description": "AWS Access Key",
        "example": "AWS_ACCESS_KEY=A3TGOBTGY4DIMRXMIYGE",
        "offender": "=A3TGOBTGY4DIMRXMIYGE",
        "comment": "Should capture aws access keys",
    },
    {
        "description": "AWS Secret Key",
        "example": "  AWSSecretKey=af60f112a534df0cc1e4d892b5768f3easefasza foo=bar",
        "offender": "AWSSecretKey=af60f112a534df0cc1e4d892b5768f3easefasza",
        "comment": "Should capture aws secret keys",
    },
    {
        "description": "AWS Secret Key",
        "example": '  AWSSecretKey="aF6/f1+2a534df0cc1e4d892b5768f3easefaszb" foo=bar',
        "offender": 'AWSSecretKey="aF6/f1+2a534df0cc1e4d892b5768f3easefaszb"',
        "comment": "Should capture aws secret keys",
    },
    {
        "description": "AWS Secret Key",
        "example": '  "aws_secret_key": "Af60f112a534df0cc1e4d892b5768f3easef/+zc" foo=bar',
        "offender": 'aws_secret_key": "Af60f112a534df0cc1e4d892b5768f3easef/+zc"',
        "comment": "Should capture aws secret keys",
    },
    {
        "description": "Potential AWS Secret Key",
        "example": "example comes from one of the AWS secret keys above",
        "offender": '"aF6/f1+2a534df0cc1e4d892b5768f3easefaszb"',
        "comment": "A slightly different capture group for the potential ones",
    },
    {
        "description": "Potential AWS Secret Key",
        "example": "example comes from one of the AWS secret keys above",
        "offender": '"Af60f112a534df0cc1e4d892b5768f3easef/+zc"',
        "comment": "A slightly different capture group for the potential ones",
    },
    {
        "description": "Potential AWS Secret Key",
        "example": "foo = 'kvVsZle45ZChqRmlmdX+tTIwNuHwRziBERNXq6Sw'",
        "offender": "'kvVsZle45ZChqRmlmdX+tTIwNuHwRziBERNXq6Sw'",
        "comment": """
        This matches the regex for an aws secret key with no other context.
        There are some limitations with how go's regex parser can handle
        lookarounds so this does the best it can to guess but may miss some
        """,
    },
    {
        "description": "Potential AWS Secret Key",
        "example": "foo = LvVsZle45ZChqRmlmdX+tTIwNuHwRziBERNXq6Sw",
        "offender": " LvVsZle45ZChqRmlmdX+tTIwNuHwRziBERNXq6Sw",
        "comment": """
        This matches the regex for an aws secret key with no other context.
        There are some limitations with how go's regex parser can handle
        lookarounds so this does the best it can to guess but may miss some
        """,
    },
    {
        "description": "Asymmetric Private Key",
        "example": "-----BEGIN PGP PRIVATE KEY-----",
        "offender": "-----BEGIN PGP PRIVATE KEY-----",
        "comment": "Should capture private key headers",
    },
    {
        "description": "Asymmetric Private Key",
        "example": "-----BEGIN OPENSSH PRIVATE KEY-----\\n0b3d576ba5a108c3b7374142bfd029920b3d576ba5a108c3b7374142bfd029920b3d576ba5a108c3b7374142bfd02992\\n-----END OPENSSH PRIVATE KEY-----",
        "offender": "-----BEGIN OPENSSH PRIVATE KEY-----",
        "comment": "Should capture private key headers",
    },
    {
        "description": "Unquoted Secret",
        "example": 'password=0b3d576ba5a108c3b7374142bfd02992 some = "other value", example="example"',
        "offender": "password=0b3d576ba5a108c3b7374142bfd02992",
        "comment": "make sure it captures the password but stops before other values",
    },
    {
        "description": "General Secret",
        "example": 'password = "0b3d576ba5a108c3b7374142bfd02992", some = "other value", example="example"',
        "offender": 'password = "0b3d576ba5a108c3b7374142bfd02992"',
        "comment": "make sure it captures the password but stops at the quote",
    },
    {
        "description": "General Secret",
        "example": 'password = "Lol-IKR-those-kids-R-Krazy"',
        "offender": 'password = "Lol-IKR-those-kids-R-Krazy"',
        "comment": "make sure mixed case with dashes is caught",
    },
    {
        "description": "General Secret",
        "example": 'password = "l0l-1kr-th0se-k1ds-r-kr4zy"',
        "offender": 'password = "l0l-1kr-th0se-k1ds-r-kr4zy"',
        "comment": "make sure lower case with dashes and numbers is caught",
    },
    {
        "description": "General Secret",
        "example": '{"password": "3ae68d9f8ccfc898ee2555a5f8f228b9", "foo": "bar"}',
        "offender": '"password": "3ae68d9f8ccfc898ee2555a5f8f228b9"',
        "comment": "make sure it captures the password but stops at the quote",
    },
    {
        "description": "General Secret",
        "example": 'password = "RAW(kx#2+c7a)"',
        "offender": 'password = "RAW(kx#2+c7a)"',
        "comment": "Make sure the entropy check allows this",
    },
    {
        "description": "General Secret",
        "example": "<password>$A3ae68d9f8ccfc898ee2555a5f8f228b9</password>",
        "offender": "<password>$A3ae68d9f8ccfc898ee2555a5f8f228b9</",
        "comment": "Make sure the password works with xml formatted stuff",
    },
    {
        "description": "General Secret",
        "example": '<FooPassword id="new" >$A3ae68d9f8ccfc898ee2555a5f8f228b9</FooPassword><bar>baz</bar>',
        "offender": '<FooPassword id="new" >$A3ae68d9f8ccfc898ee2555a5f8f228b9</',
        "comment": "Make sure it can handle weird formatted stuff",
    },
    {
        "description": "General Secret",
        "example": 'secret = "$A0b3d576ba5a108c3b7374142bfd02992", some = "other value"',
        "offender": 'secret = "$A0b3d576ba5a108c3b7374142bfd02992"',
        "comment": "make sure it captures the secret but stops at the quote",
    },
    {
        "description": "General Secret",
        "example": 'secret_key = "766a929d93c9ef30ce3d72d6384eb6fa"',
        "offender": 'secret_key = "766a929d93c9ef30ce3d72d6384eb6fa"',
        "comment": "make sure it captures the secret and can include _key",
    },
    {
        "description": "General Secret",
        "example": 'secret-key = "766a929d93c9ef30ce3d72d6384eb6fa"',
        "offender": 'secret-key = "766a929d93c9ef30ce3d72d6384eb6fa"',
        "comment": "make sure it captures the secret and can include -key",
    },
    {
        "description": "General Secret",
        "example": '{"secret": "$A3ae68d9f8ccfc898ee2555a5f8f228b9", "foo": "bar"}',
        "offender": '"secret": "$A3ae68d9f8ccfc898ee2555a5f8f228b9"',
        "comment": "make sure it captures the secret but stops at the quote",
    },
    {
        "description": "General Secret",
        "example": 'secret = "RAW(kx#2+c7a)"',
        "offender": 'secret = "RAW(kx#2+c7a)"',
        "comment": "Make sure the entropy check allows this",
    },
    {
        "description": "General Secret",
        "example": "<secret>$A3ae68d9f8ccfc898ee2555a5f8f228b9</secret>",
        "offender": "<secret>$A3ae68d9f8ccfc898ee2555a5f8f228b9</",
        "comment": "Make sure the secret works with xml formatted stuff",
    },
    {
        "description": "General Secret",
        "example": '<FooSecret id="new" >$A3ae68d9f8ccfc898ee2555a5f8f228b9</FooSecret><bar>baz</bar>',
        "offender": '<FooSecret id="new" >$A3ae68d9f8ccfc898ee2555a5f8f228b9</',
        "comment": "Make sure it can handle weird formatted stuff",
    },
    {
        "description": "Htpasswd Files",
        "example": "bob123:$apr1$FaPYZHMz$jYiw5.ExmVKeLbjex5Jvr34uA/",
        "offender": "bob123:$apr1$FaPYZHMz$jYiw5.ExmVKeLbjex5Jvr34uA/",
        "comment": "Test to see that htpasswd files show up",
        "filename": "my-htpasswd-file",
    },
    {
        "description": "Htpasswd Files",
        "example": "newUser2:$apr1$mCCHcVhc$ExmVKeLbjex5Jvr34uA/",
        "offender": "newUser2:$apr1$mCCHcVhc$ExmVKeLbjex5Jvr34uA/",
        "comment": "Test to see that htpasswd files show up",
        "filename": "my-htpasswd-file",
    },
    {
        "description": "WP-Config",
        "example": "define(    'DB_PASSWORD', '$c8e$743df9d386d895}');",
        "offender": "define(    'DB_PASSWORD', '$c8e$743df9d386d895}')",
    },
    {
        "description": "WP-Config",
        "example": "define('AUTH_KEY',         'kzgllO;k$F_-W68 Fl*iEekX;-pn =fNS(;c9nDKt;5RW(&jtESXsW9+PhQFS!Tv');",
        "offender": "define('AUTH_KEY',         'kzgllO;k$F_-W68 Fl*iEekX;-pn =fNS(;c9nDKt;5RW(&jtESXsW9+PhQFS!Tv')",
    },
    {
        "description": "WP-Config",
        "example": "define('SECURE_AUTH_KEY',  ',,F|NHKh>=+y.gy%B32Ff!s~MJp$L,]~xEK|e3H)7| 4hX]!/Ky@V(esZa?0D#H*');",
        "offender": "define('SECURE_AUTH_KEY',  ',,F|NHKh>=+y.gy%B32Ff!s~MJp$L,]~xEK|e3H)7| 4hX]!/Ky@V(esZa?0D#H*')",
    },
    {
        "description": "WP-Config",
        "example": "define('LOGGED_IN_KEY',    'k7o7@~oee{u,MG KFBJq0M`-iJ0H0hs)m-@i/RsgwZ{No~JQ+)2A<Ryd+|t<8.[a');",
        "offender": "define('LOGGED_IN_KEY',    'k7o7@~oee{u,MG KFBJq0M`-iJ0H0hs)m-@i/RsgwZ{No~JQ+)2A<Ryd+|t<8.[a')",
    },
    {
        "description": "WP-Config",
        "example": "define('NONCE_KEY',        'f54j6Auj0NT8g;5-^zk}yZ`vN^8/7!6=%5bS>GUu{04~#E*a~WdGX<%>Aa<Ke}K8');",
        "offender": "define('NONCE_KEY',        'f54j6Auj0NT8g;5-^zk}yZ`vN^8/7!6=%5bS>GUu{04~#E*a~WdGX<%>Aa<Ke}K8')",
    },
    {
        "description": "WP-Config",
        "example": "define('AUTH_SALT',        '?PULIL7?y%Ub=[~rw+5Pg^!$UrrOpn*Pr(MFBdF-+ZMH#oKsZ{KskZY9m/i|<pkK');",
        "offender": "define('AUTH_SALT',        '?PULIL7?y%Ub=[~rw+5Pg^!$UrrOpn*Pr(MFBdF-+ZMH#oKsZ{KskZY9m/i|<pkK')",
    },
    {
        "description": "WP-Config",
        "example": "define('SECURE_AUTH_SALT', 'of~0;WuAmEBP4~rfM)1Q.Oc0U=g^t|d%h.Ui8w<v4;A47FGs0}@Hk>&g?p*hDoQs');",
        "offender": "define('SECURE_AUTH_SALT', 'of~0;WuAmEBP4~rfM)1Q.Oc0U=g^t|d%h.Ui8w<v4;A47FGs0}@Hk>&g?p*hDoQs')",
    },
    {
        "description": "WP-Config",
        "example": "define('LOGGED_IN_SALT',   'WTc*{p+XT((_#^NxhoU)[7NAg};Q?`+0wpkia>oA]hF-TB2lC GM!~aM=-Hqw4,+');",
        "offender": "define('LOGGED_IN_SALT',   'WTc*{p+XT((_#^NxhoU)[7NAg};Q?`+0wpkia>oA]hF-TB2lC GM!~aM=-Hqw4,+')",
    },
    {
        "description": "WP-Config",
        "example": "define('NONCE_SALT',       '^[_9^w_,UPMuJ2-}7=y<|v=y$#xftY[klEW3zt,Y}bB tG4d):p9Fd;$imF[lGqR');",
        "offender": "define('NONCE_SALT',       '^[_9^w_,UPMuJ2-}7=y<|v=y$#xftY[klEW3zt,Y}bB tG4d):p9Fd;$imF[lGqR')",
    },
    {
        "description": "GitHub personal access token",
        "example": "<access-token>ghp_16C7e42F292c6912E7710c838347Ae178B4a</access-token>",
        "offender": "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/",
    },
    {
        "description": "GitHub oauth access token",
        "example": "token='gho_16C7e42F292c6912E7710c838347Ae178B4a'",
        "offender": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/",
    },
    {
        "description": "GitHub user-to-server token",
        "example": "'gt-token': 'ghu_16C7e42F292c6912E7710c838347Ae178B4a'",
        "offender": "ghu_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/",
    },
    {
        "description": "GitHub server-to-server token",
        "example": "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
        "offender": "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/",
    },
    {
        "description": "GitHub refresh token",
        "example": "ghr_16C7e42F292c6912E7710c838347Ae178B4a",
        "offender": "ghr_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/",
    },
    {
        "description": "PyPI Upload Token",
        "example": "Foo bar baz pypi-AgEIcHlwaS5vcmcCJDU0ZTIxMWRiLWNlMjYtNDM3ZS05YjJlLWYzYTk5NmE2NGJjMgACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0AAAYgWzvnJ7sF-57Jw_YGg04aZTPCeuRpXrHBhAsPRfofZGc foo",
        "offender": "pypi-AgEIcHlwaS5vcmcCJDU0ZTIxMWRiLWNlMjYtNDM3ZS05YjJlLWYzYTk5NmE2NGJjMgACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0AAAYgWzvnJ7sF-57Jw_YGg04aZTPCeuRpXrHBhAsPRfofZGc",
        "comment": "Should catch PyPI upload tokens",
    },
    {
        "description": "General Secret",
        "example": 'SECRET_KEY = "zeu#xlk35rk7$b0o_hg7bfr@602da3b6f339dbe9a1054228a74edd6b"',
        "offender": 'SECRET_KEY = "zeu#xlk35rk7$b0o_hg7bfr@602da3b6f339dbe9a1054228a74edd6b"',
        "comment": "Should capture django secret keys",
        "filename": "settings.py",
    },
    {
        "description": "HTTP Basic Auth Password",
        "example": "http://username:1d902de68e4113f5855a6c88314cec6a@host/foo/bar/baz",
        "offender": "http://username:1d902de68e4113f5855a6c88314cec6a@host",
        "comment": "Should capture basic auth for http",
    },
    {
        "description": "Basic Auth Password",
        "example": "example comes from one of the HTTP Basic Auth Password rule above",
        "offender": "://username:1d902de68e4113f5855a6c88314cec6a@host",
        "comment": "Should capture basic auth for http",
    },
    {
        "description": "HTTP Basic Auth Password",
        "example": "https://username:2d902de68e4113f5855a6c88314cec6a@host",
        "offender": "https://username:2d902de68e4113f5855a6c88314cec6a@host",
        "comment": "Should capture basic auth for https",
    },
    {
        "description": "Basic Auth Password",
        "example": "example comes from one of the HTTP Basic Auth Password rule above",
        "offender": "://username:2d902de68e4113f5855a6c88314cec6a@host",
        "comment": "Should capture basic auth for https",
    },
    {
        "description": "Basic Auth Password",
        "example": "rsync://username:9d902de68e4113f5855a6c88314cec6a@host",
        "offender": "://username:9d902de68e4113f5855a6c88314cec6a@host",
        "comment": "Should catch protocols other than http",
    },
    {
        "description": "SendGrid API Key",
        "example": "key='SG.9C07-916Ee9X80Yd0b32M3f27922.9C07-916-e9XL0Yaaxad0b32M3f27922'",
        "offender": "'SG.9C07-916Ee9X80Yd0b32M3f27922.9C07-916-e9XL0Yaaxad0b32M3f27922",
        "comment": "Should capture a SG api key",
    },
    {
        "description": "Container Registry Authentication",
        "example": 'reg := registry.New("quay.io", "user", "09e25b6fc894c83868715a8cce1ba7d2") // remove later',
        "offender": 'registry.New("quay.io", "user", "09e25b6fc894c83868715a8cce1ba7d2")',
        "comment": "Should capture container registry passwords.",
    },
]

SHOULD_NOT_MATCH = [
    {
        "example": "AWS_ACCESS_KEY=A3TGOBTGY4DIMRXMIYGE #gitleaks:allow",
        "comment": "Allowed by gitleaks:allow",
    },
    {
        "example": "AWS_ACCESS_KEY=A3TGOBTGY4DIMRXMIYGE // gitleaks:allow",
        "comment": "Allowed by gitleaks:allow different comment type",
    },
    {
        "example": 'WithSG.InterfacePropertiesFormat.IPConfigurations',
        "comment": "Looks really close to a SendGrid API Key's format",
    },
    {
        "example": 'requiredSecret="[SOME_RANDOM_SECRET]"',
        "comment": "Placeholder secret",
    },
    {
        "example": "xoxp-some-slack-access-token-these-are-very-long-and-start-with-xo",
        "comment": "Placeholder slack token",
    },
    {
        "example": "'token': 'xoxa-123456789abcdef',",
        "comment": "Placeholder slack token",
    },
    {
        "example": '.secret": "spec.some.path[*].secretRef",',
        "comment": "Path to a secret and not a real secret",
    },
    {
        "example": 'PASSWORD="&lt;password_for_some_account&gt;"',
        "comment": "Placeholder with markup",
    },
    {
        "example": "secret=00000000-0000-0000-0000-000000000000",
        "comment": "Not a real secret",
    },
    {
        "example": "Secret=true|false",
        "comment": "Not a real secret",
    },
    {
        "example": " b/drivers/media/platform/bcm2835/Kconfig",
        "comment": "Meets the criteria for a potential aws secret key",
    },
    {
        "example": "schema://user:keylime@host:port/",
        "comment": "Common placeholder account",
    },
    {
        "example": "schema://user:postgres@host:port/",
        "comment": "Common placeholder account",
    },
    {
        "example": "mysql://username:userpass@host:port/fasdfasdfasdf",
        "comment": "Things ending in 'pass' are probably placeholders'",
    },
    {
        "example": "# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)",
        "comment": "comment in a htpasswd file",
        "filename": "foo.htpasswd",
    },
    {
        "example": 'oc login $(oc whoami --show-server) --insecure-skip-tls-verify --username=kubeadmin --password="\$KUBEADMIN_PASS" ',
        "comment": "env variable",
    },
    {
        "example": "-----BEGIN PGP PRIVATE KEY-----",
        "filename": "test/testec-p112r1.pem",
        "comment": "Common test files in the open ssl project and others",
    },
    {
        "example": 'root_password: "PROVIDE-A-PASSWORD-SALT"',
        "comment": "placeholder",
    },
    {
        "example": '"vault-secret": "NamespaceOpenshiftResourceVaultSecret_v1"',
        "comment": "secret ref",
    },
    {
        "example": 'String secret = "&secretKey=RAW(" + s3_secretKey + ")"',
        "comment": "placeholder",
    },
    {
        "example": '"secret":"some-secret-CHANGEME"',
        "comment": "placeholder",
    },
    {
        "example": 'secret="GITHUB_TOKEN=${GITHUB_TOKEN}"',
        "comment": "setting a variable",
    },
    {
        "example": 'token_secret="$(KUBECONFIG="$target" kubectl get sa "$sa" -n "$namespace" -o json |',
        "comment": "part of a sub command",
    },
    {
        "example": "asdfasdfaeaAIzaOObST8cGSeh3cYNvEGXEXY9BShQx1EtRdfZasdfasmlajasdfasdfasdf",
        "comment": "contains a substring that looks like a google api key",
    },
    {
        "example": 'secret: "[[.Some.Build.Secret]]"',
        "comment": "Placeholder",
    },
    {
        "example": "password=\(password)",
        "comment": "Placeholder",
    },
    {
        "example": "password=#{password}",
        "comment": "Placeholder",
    },
    {
        "example": "password=`generate-password`",
        "comment": "Shell command",
    },
    {
        "example": "password=#REPLACE_ME#",
        "comment": "Placeholder",
    },
    {
        "example": "'-s klmnopqrstuvwxyz12345ABCD987654321efghij'",
        "comment": "Placeholder",
    },
    {
        "example": "http://mirror.centos.org/centos/8-stream/BaseOS/aarch64/os/Packages/libffi-3.1-23.el8.aarch64.rpm",
        "comment": "Happens to have the right number of characters for an AWS key inside part of the URL",
    },
    {
        "example": "7e90d3e171128c6e6fa038ff3cb5f387fb=7e90d3e171128c6e6fa038ff3cb5f387",
        "comment": "Not a facebook key",
    },
    {
        "example": "-----BEGIN EC PRIVATE KEY-----\\nkey\\n-----END EC PRIVATE KEY-----",
        "comment": "Shouldn't match such a short key",
    },
    {
        "example": "-----BEGIN RSA PRIVATE KEY-----\\nREPLACE_ME\\n-----END RSA PRIVATE KEY-----",
        "comment": "Shouldn't match such a short key",
    },
    {
        "example": "-----BEGIN PRIVATE KEY-----\\nMII.....RSA KEY WITHOUT LINEBREAKS\\n-----END PRIVATE KEY-----",
        "comment": "Shouldn't match an inline key with spaces in it",
    },
    {
        "example": 'password = "${PASSWORD_PLACEHOLDER_123}", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'password: "SuperSecretPassword!"',
        "comment": "placeholder value",
    },
    {
        "example": "auth.password = \"#{File.exists?('/some/path') ? open('/some/path','r') do |f|f.read end : ''}\"",
        "comment": "placeholder value with quotes and code",
    },
    {
        "example": 'password = "example-9b5a699bc0dc8211f103a9a305b01a51", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "quickstart-9b5a699bc0dc8211f103a9a305b01a51", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "9b5a699bc0dc8211f103a9a305b01a51-example", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": "service.binding/db_password: 'path={.spec.databasePassword}'",
        "comment": "placeholder value",
    },
    {
        "example": 'databasePassword: "samplepwd"',
        "comment": "placeholder value",
    },
    {
        "example": 'password:  "the-thing-is-required",',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "update-your-postgres-pass-here"',
        "comment": "placeholder value",
    },
    {
        "example": 'admin_password: "autogenerated_stuff"',
        "comment": "placeholder value",
    },
    {
        "example": 'admin_password = "this-is-not-real!"',
        "comment": "placeholder value",
    },
    {
        "example": 'admin_password = "NotActuallyApplied!"',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "[%PASSWORD_PLACEHOLDER_123%]", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "$(PASSWORD_PLACEHOLDER_123)", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'cps.Data["metadata"] = []byte("password: " + tokenValue + "\nusername: NEW_VALUE")',
        "comment": "placeholder value",
    },
    {
        "example": 'password="`+yaml.GetConfig().Password+`"',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "{PASSWORD_PLACEHOLDER_123}", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": '{"password": "${PASSWORD_PLACEHOLDER_123}", "foo": "bar"}',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "<SOME_PLACEHOLDER>", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "%SOME_PLACEHOLDER_123%", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": "admin_password='ADMIN_PASSWORD_HERE'",
        "comment": "placeholder value",
    },
    {
        "example": 'export PGPASSWORD="\$(POSTGRESQL_PASSWORD)"',
        "comment": "placeholder value",
    },
    {
        "example": 'Password: "@@FILE:/some/file/path@@"',
        "comment": "placeholder value",
    },
    {
        "example": '"password="+privateDataPlaceholder()+"&"',
        "comment": "placeholder value",
    },
    {
        "example": 'password = "foo", some = "other value"',
        "comment": "entropy check",
    },
    {
        "example": 'password: ".odc-multiple-key-selector button"',
        "comment": "most likely not a password, has a space in it",
    },
    {
        "example": "password=', listKeys(resourceId('",
        "comment": "most likely not a password, has a space in it",
    },
    {
        "example": 'password: "exp_password" or "{{ example_password }}"',
        "comment": "allow list check",
    },
    {
        "example": '<FooPassword id="new" >{{PLACEHOLDER}}</FooPassword><bar>baz</bar>',
        "comment": "Ignore placeholders",
    },
    {
        "example": '<FooPassword id="new" >{PLACEHOLDER}</FooPassword><bar>baz</bar>',
        "comment": "Ignore placeholders",
    },
    {
        "example": '<FooPassword id="new" >$PLACEHOLDER_123</FooPassword><bar>baz</bar>',
        "comment": "Ignore placeholders",
    },
    {
        "example": '<FooPassword id="new" >${PLACEHOLDER}</FooPassword><bar>baz</bar>',
        "comment": "Ignore placeholders",
    },
    {
        "example": 'password="secret12345"',
        "comment": "allow list check",
    },
    {
        "example": 'password="password_to_replace"',
        "comment": "allow list check",
    },
    {
        "example": 'password="some_placeholder_passwd"',
        "comment": "allow list check",
    },
    {
        "example": 'password="some_placeholder_pwd"',
        "comment": "allow list check",
    },
    {
        "example": 'password="some_placeholder-pwd"',
        "comment": "allow list check",
    },
    {
        "example": 'password="passwort_to_replace"',
        "comment": "allow list check (spelling error)",
    },
    {
        "example": 'password="passord_to_replace"',
        "comment": "allow list check (spelling error)",
    },
    {
        "example": '{"data":{"some-secret":"base64string"}}',
        "comment": "placeholder value",
    },
    {
        "example": 'access_token_secret="GITHUB_ACCESS_TOKEN"',
        "comment": "placeholder value",
    },
    {
        "example": 'get_secret="foo_client_id"',
        "comment": "placeholder value",
    },
    {
        "example": 'get_secret="foo_key_private"',
        "comment": "placeholder value",
    },
    {
        "example": "pullSecret: '%{pull_secret}'",
        "comment": "placeholder value",
    },
    {
        "example": "secret = 'HFYp7dGQhQ7G03juqw373JlSw8K/K7MDENG/bPxRfiCY' //nolint:gosec",
        "comment": "placeholder value",
    },
    {
        "example": "secret = 'HFYp7dGQhQ7G03juqw373JlSw8K/K7MDENG/EXAMPLEKEY'",
        "comment": "placeholder value",
    },
    {
        "example": 'export SOME_SECRET="$SOME_ENV_VAR-value"',
        "comment": "placeholder value",
    },
    {
        "example": 'secret = "${SECRET_PLACEHOLDER_123}", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'secret = "$(SECRET_PLACEHOLDER_123)", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'secret = "[%SECRET_PLACEHOLDER_123%]", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'secret: ".odc-multiple-key-selector button"',
        "comment": "most likely not a secret, has a space in it",
    },
    {
        "example": 'cps.Data["metadata"] = []byte("secret: " + tokenValue + "\nusername: NEW_VALUE")',
        "comment": "placeholder value",
    },
    {
        "example": "<UserSecretsId>c007cd12-1fe7-4843-947e-ddecfc0d8913</UserSecretsId>",
        "comment": "UUID should not be matched",
    },
    {
        "example": 'secret="c007cd12-1fe7-4843-947e-ddecfc0d8913"',
        "comment": "UUID should not be matched",
    },
    {
        "example": 'servers: \'[{ "id": "sonatype", "username": "$SONATYPE_BOT_USERNAME", "password": "$SONATYPE_BOT_TOKEN" }]\'',
        "comment": "placeholder value",
    },
    {
        "example": 'secret = "{SECRET_PLACEHOLDER_123}", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'secret = "%SECRET_PLACEHOLDER_123%", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'session_secret: "${SESSION_SECRET}="',
        "comment": "placeholder value",
    },
    {
        "example": '{"secret": "${SECRET_PLACEHOLDER_123}", "foo": "bar"}',
        "comment": "placeholder value",
    },
    {
        "example": 'secret = "<SOME_PLACEHOLDER>", some = "other value"',
        "comment": "placeholder value",
    },
    {
        "example": 'secret = "foo", some = "other value"',
        "comment": "entropy check",
    },
    {
        "example": 'in.Secret = "abcdef0123456789"',
        "comment": "placeholder value",
    },
    {
        "example": "secret: 'foo-credentials'",
        "comment": "placeholder value",
    },
    {
        "example": 'secret: "k8s-infra-key"',
        "comment": "reference",
    },
    {
        "example": '"secret": "insert user Secret",',
        "comment": "allow list check (ends with <space>secret)",
    },
    {
        "example": '"secret": "insert-abc123-Secret",',
        "comment": "allow list check (ends with -secret)",
    },
    {
        "example": '"secret": "insert-abc123.json",',
        "comment": "allow list check (ends with .json)",
    },
    {
        "example": '"secret": "insert-abc123-data",',
        "comment": "allow list check (ends with -data)",
    },
    {
        "example": '"secret": "insert-abc123-kubeconfig",',
        "comment": "allow list check (ends with -kubeconfig)",
    },
    {
        "example": '"secret": "insert-abc123.Secret",',
        "comment": "allow list check (ends with .secret)",
    },
    {
        "example": '<FooSecret id="new" >{{PLACEHOLDER}}</FooSecret><bar>baz</bar>',
        "comment": "Ignore placeholders",
    },
    {
        "example": '<FooSecret id="new" >{PLACEHOLDER}</FooSecret><bar>baz</bar>',
        "comment": "Ignore placeholders",
    },
    {
        "example": '<FooSecret id="new" >${PLACEHOLDER}</FooSecret><bar>baz</bar>',
        "comment": "Ignore placeholders",
    },
    {
        "example": 'secret="secret"',
        "comment": "allow list check",
    },
    {
        "example": 'secret="secret_to_replace"',
        "comment": "allow list check",
    },
    {
        "example": 'secret": "Problem with creating secret {{error}}"',
        "comment": "looks like a sentence",
    },
    {
        "example": "bob123:example",
        "comment": "Should be too low-entropy",
        "filename": "my-htpasswd-file",
    },
    {
        "example": "user456:$jhI1AC9LG01KrQS$FzPCZHMe$jXiw5.8UevKx29pRH4AsT/",
        "comment": "Should not match because it's not in a htpasswd file",
    },
    {
        "example": '"password": "paSSwOrD for kubernetes user",',
        "comment": "allow list check (starts with pasword<space>",
    },
    {
        "example": '"secret": "client-secret-for-service-principal",',
        "comment": "allow list check (starts with client)",
    },
    {
        "example": '"password": "SUPER-SECRET-123"',
        "comment": "Too low entropy",
    },
    {
        "example": '"password": "insert user PasSworD",',
        "comment": "allow list check (ends with <space>password)",
    },
    {
        "example": '"password": "insert-user-PasSworD",',
        "comment": "allow list check (ends with -password)",
    },
    {
        "example": '"secret": "awx-postgres-configuration",',
        "comment": "allow list check (ends with -configuration)",
    },
    {
        "example": '"secret": "multicluster-mongodb-client-cert",',
        "comment": "allow list check (ends with -cert)",
    },
    {
        "example": "_Somef0lder/or/Somepath/that0snotakeyyepa.sh",
        "comment": "this is close to the regex for an aws key",
    },
    {
        "example": '"secret": "multicluster-mongodb-client-certification",',
        "comment": "allow list check (ends with -cert)",
    },
    {
        "example": '"secret": "multicluster-mongodb-client-authentication",',
        "comment": "allow list check (ends with -authentication)",
    },
    {
        "example": '"secret": "reposure-registry",',
        "comment": "allow list check (ends with -registry)",
    },
    {
        "example": '"secret": "reposure-registry-secrets",',
        "comment": "allow list check (ends with -secrets)",
    },
    {
        "example": '"password": "insert-user-123-kubeconfig",',
        "comment": "allow list check (ends with -kubeconfig)",
    },
    {
        "example": '"password": "insert-user-123.json",',
        "comment": "allow list check (ends with .json)",
    },
    {
        "example": '"password": "insert-user-123-data",',
        "comment": "allow list check (ends with -data)",
    },
    {
        "example": '"password": "insert-user.PasSworD",',
        "comment": "allow list check (ends with .password)",
    },
    {
        "example": '"ConfigMap/Secret": "ConfigMap/Secret"',
        "comment": "Make sure it doesn't match /Secret",
    },
    {
        "example": 'password = "dev-pass", some = "other value"',
        "comment": "entropy check",
    },
    {
        "example": 'password = "foobar", some = "other value"',
        "comment": "entropy check",
    },
    {
        "example": "define('AUTH_KEY', '${AUTH_KEY}');",
        "comment": "placeholder value",
    },
    {
        "example": "define('AUTH_KEY', '{{AUTH_KEY}}');",
        "comment": "placeholder value",
    },
    {
        "example": "ghr_16C7e42F292c69",
        "comment": "It is too short to be a real token",
    },
    {
        "example": "administration_role_arn: arn:aws:iam::1234567890:role/AWSCloudFormationStackSetAdministrationRole",
        "comment": "ignore these arn matches",
    },
    {
        "example": "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        "comment": "ignore these arn matches",
    },
    {
        "example": "errorMessage: this.props.t('public~You must specify an HTPasswd file.')",
        "comment": "Try to avoid fps in a htpassword file",
        "filename": "my-htpasswd-file",
    },
    {
        "example": "secret: '/var/run/secret/secret.yml'",
        "comment": "This is a yaml config file, should support both .yaml and .yml in the allow list",
    },
    {
        "example": 'Password = "$A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS"',
        "comment": "Ignore general passwords in in the azure-cli repos",
        "filename": "azure-cli/test",
    },
    {
        "example": 'secret = "$A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS", some = "other value"',
        "comment": "Ignore general secrets in in the azure-cli repos",
        "filename": "azure-cli/test",
    },
    {
        "example": '"hashed_secret": "972edb79d7c2e4374689572fb6c4ee7b",',
        "comment": "Ignore .secrets.baseline files",
        "filename": ".secrets.baseline",
    },
    {
        "example": '"Password:"),d?_.a.createElement("',
        "comment": "Should not catch snipets of code",
    },
    {
        "example": 'password: ").append(toIndentedString(password)).append("',
        "comment": "Should not catch snipets of code",
    },
    {
        "example": '"secret:"),d?_.a.createElement("',
        "comment": "Should not catch snipets of code",
    },
    {
        "example": '"secret:" ),d?_.a.createElement("',
        "comment": "Should not catch snipets of code",
    },
    {
        "example": 'SECRET_KEY = "django-insecure-zeu#xlk35rk7$b0o_hg7bfr@60A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS"',
        "comment": "Should not catch fake django keys",
        "filename": "settings.py",
    },
    {
        "example": "SECRET_KEY = 'django-insecure-q9$s5rGwuLlu&a6_#%A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS'",
        "comment": "Should not catch fake django keys in any file",
    },
    {
        "example": 'nexus_proxy_password = "A3QuDLm2Ukhsae68d9f9ccjhI1AC9LG01KrQS"  # nosec',
        "comment": "Support # nosec tag",
    },
    {
        "example": 'const someSecret = "SomeStubbedOutThing"    // #nosec G101 -- This is a false positive',
        "comment": "Support #nosec tag",
    },
    {
        "example": 'password":"material/form-textbox-password.svg"',
        "comment": "Ignore file references for passwords and secrets",
    },
    {
        "example": 'password":"material/form-textbox-password.svg"',
        "comment": "Ignore file references for passwords and secrets",
    },
    {
        "example": 'secret":"material/form-textbox-password.png"',
        "comment": "Ignore file references for passwords and secrets",
    },
    {
        "example": 'password":"material/form-textbox-password.jpeg"',
        "comment": "Ignore file references for passwords and secrets",
    },
    {
        "example": 'password":"some/path/to/password.txt"',
        "comment": "Ignore file references for passwords and secrets",
    },
    {
        "example": 'secret": "some/path/to/secret.txt"',
        "comment": "Ignore file references for passwords and secrets",
    },
    {
        "example": 'secret="bf440e4268dA3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS"',
        "comment": "Ignore quickstarts",
        "filename": "foo/quarkus-quickstarts/bar/secret.txt",
    },
    {
        "example": 'if awsEnvVars[i].Name == RegistryStorageS3RegionendpointEnvVarKey && bsl.Spec.Config[S3URL] != "" {',
        "comment": "This isn't an AWS secret key! I promise!",
    },
    {
        "example": "bob423:$apr1$FaA3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS/",
        "comment": "Ignore code source files that has htpasswd in the name",
        "filename": "some-htpasswd-file.go",
    },
    {
        "example": "bob523:$apr1$FaA3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQX/",
        "comment": "Ignore code source files that has htpasswd in the name",
        "filename": "some-htpasswd-file.js",
    },
    {
        "example": "bob523:$apr1$FaA3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQX/",
        "comment": "Ignore code source files that has htpasswd in the name",
        "filename": "some-htpasswd-file.py",
    },
    {
        "example": 'password = "lol-ikr-those-kids-r-krazy"',
        "comment": "make sure lower case with dashes is NOT caught",
    },
    {
        "example": 'secret = "lol-ikr-those-kids-r-krazy"',
        "comment": "make sure lower case with dashes is NOT caught",
    },
    {
        "example": 'secret = "K8s-lol-ikr-those-kids-r-krazy"',
        "comment": "some numbers and upper case are fine as long as a good portion is lower with dashes",
    },
    {
        "example": 'secret = "/run/kubernetes/secrets/oscontainer-registry/dockercfg"',
        "comment": "Things in '/run/' should be ignored",
    },
    {
        "example": 'secret = "/var/run/secrets/atomic-reactor/v2-registry-dockercfg"',
        "comment": "Things in '/var/run/' should be ignored",
    },
    {
        "example": 'secret = "/path/to/password/file"',
        "comment": "Things like '/path/' should be ignored",
    },
    {
        "example": "define('DB_PASSWORD', 'password');",
        "comment": "Placeholder value for wordpress passwords",
    },
    {
        "example": "GITHUB_PERSONAL_ACCESS_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "comment": "Placeholder value for an access token",
    },
    {
        "example": "#https://example.com/look/some/docs?cHViOnJlZGhhdA==\nuser: {{new_pass}}",
        "comment": "Ignore yaml files for the htpassword check",
        "filename": "htpasswd.yml",
    },
    {
        "example": "#https://example.com/look/some/docs?cHViOnJlZGhhdA==\nuser: {{new_pass}}",
        "comment": "Ignore yaml files for the htpassword check",
        "filename": "htpasswd.yaml",
    },
    {
        "example": "password='A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQSA3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS'",
        "comment": "Ignore venv site-packages",
        "filename": "venv/lib/python3.9/site-packages/some-cred",
    },
    {
        "example": "password='A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQSA3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS'",
        "comment": "Ignore venv site-packages",
        "filename": "venv3/lib/python3.9/site-packages/some-cred",
    },
    {
        "example": "some-random-thing=key-fb959af04c12d5d66091256c2b2076d0",
        "comment": "Should not capture things formated like a mg api key without mg/mailgun in the prefix",
    },
    {
        "example": "https://examle.com/foo:current@Cacheable",
        "comment": "Just a URL - no username or pass",
    },
    {
        "example": "https://%q:%q@github.com",
        "comment": "Basic Auth Placeholder",
    },
    {
        "example": "https://$(USER):$(TOKEN)@quay.io",
        "comment": "Basic Auth Placeholder",
    },
    {
        "example": "https://${USER}:${TOKEN}@quay.io",
        "comment": "Basic Auth Placeholder",
    },
    {
        "example": "https://{USER}:{TOKEN}@quay.io",
        "comment": "Basic Auth Placeholder",
    },
    {
        "example": "https://$USER:$TOKEN@quay.io",
        "comment": "Basic Auth Placeholder",
    },
    {
        "example": "PROJECT_URL=https://user:[TOKEN]@example.com",
        "comment": "Basic Auth Placeholder",
    },
    {
        "example": "https://$USER:some-placeholder-token@quay.io",
        "comment": "Basic Auth Placeholder",
    },
    {
        "example": "https://$USER:password-foo-bar-baz@quay.io",
        "comment": "Basic Auth Placeholder",
    },
    {
        "example": "GENERATED_PASSWORD=$(openssl rand -hex 16)",
        "comment": "generated password",
    },
    {
        "example": "GENERATED_PASSWORD=${FOO}",
        "comment": "placheholder password",
    },
    {
        "example": "os_password=sys.argv[3]",
        "comment": "from code",
    },
    {
        "example": 'password="SOME_PREFIX_WITH_A_${variable}"',
        "comment": "a placeholder value",
    },
    {
        "example": 'secret="SOME_PREFIX_WITH_A_${variable}"',
        "comment": "a placeholder value",
    },
    {
        "example": 'define("DB_HOST", "localhost");',
        "comment": "ignore localhost db host in wp-config",
    },
    {
        "example": "token: xoxb-1234-56789abcdefghijklmnop",
        "comment": "ignore placeholder slack-token",
    },
    {
        "example": "password=\$MIRROR_OS_PASS&#34;",
        "comment": "ignore placeholder password",
    },
    {
        "example": "password=&#34;foobarbaz&#34;,",
        "comment": "ignore likely documentation",
    },
    {
        "example": "password=\\u0026#34;foobarbaz&#34;,",
        "comment": "ignore likely documentation",
    },
    {
        "example": "secret=foo-baz_.baz",
        "comment": "ignore likely placeholders",
    },
    {
        "example": 'AWS_TOKEN = "ABCDEFGHIJKLMNOPQRSTVWXYZabcdefghijklmnopqrstvwxyz0123=="',
        "comment": "Fake token",
    },
    {
        "example": 'password="placeholder-password.12345"',
        "comment": "Fake token",
    },
    {
        "example": 'password: "SomeSecretPassw0rd"',
        "comment": "Password placeholder",
    },
    {
        "example": 'password: "SomeSecretPassword"',
        "comment": "Password placeholder",
    },
    {
        "example": 'password: "SomeSecretPasswd"',
        "comment": "Password placeholder",
    },
    {
        "example": "https://\${GHUSER}:\${GHTOKEN}@github.com",
        "comment": "Basic auth placeholder",
    },
    {
        "example": "password=\$MIRROR_OS_PASS&#34;",
        "comment": "Placeholder",
    },
    {
        "example": "SECRET=&quot;your</span><span",
        "comment": "Has HTML",
    },
    {
        "example": "password===this.options.password}var",
        "comment": "Just a comparison",
    },
    {
        "example": "secret=@(some_client_secret)",
        "comment": "Unquoted secret placeholder",
    },
    {
        "example": "PASSWORD=${DatabasePassword:?",
        "comment": "Unquoted secret placeholder",
    },
    {
        "example": "PASSWORD=.*/foobarbaz2aAfaea",
        "comment": "Part of a regex for replacing passwords",
    },
    {
        "example": "PASSWORD=\\u90DB\\u10L8\\u10XB\\u1098",
        "comment": "ignore unicode snippets for now",
    },
    {
        "example": "aws_secret_access_key = ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234567890",
        "comment": "AWS key placeholder",
    },
    {
        "example": "webhook_secret: 'https://www.example.com',",
        "comment": "Placeholder secret",
    },
]


class TestGitLeaks(TestCase):
    test_dir = Path(__file__).resolve().parent
    patterns_path = test_dir.joinpath(
        "..", "..", "..", "target", "patterns", "gitleaks", "7.6.1",
    )
    maxDiff = 10000

    def setUp(self):
        self.test_pattern_dir = Path("/tmp/leaktk-patterns")

        # Start fresh
        if self.test_pattern_dir.is_dir():
            shutil.rmtree(self.test_pattern_dir)

        self.test_pattern_dir.mkdir(parents=True)

        # Write everything (including the specific ones) to the test file)
        general_test_file_path = self.test_pattern_dir.joinpath("general-test")
        with open(general_test_file_path, "w+") as general_test_file:
            general_test_file.write(
                "\n".join(
                    entry["example"]
                    for entry in SHOULD_NOT_MATCH + SHOULD_MATCH
                    if not "filename" in entry
                )
            )

        # Handle ones with custom filenames
        for entry in SHOULD_NOT_MATCH + SHOULD_MATCH:
            if "filename" not in entry:
                continue

            custom_file_path = self.test_pattern_dir.joinpath(entry["filename"])

            if not custom_file_path.parent.is_dir():
                custom_file_path.parent.mkdir(parents=True)

            with open(custom_file_path, "a+") as custom_file:
                custom_file.write(entry["example"] + "\n")

    def test_patterns(self):
        """
        Run gitleaks against the general test contents using the latest patterns
        """
        completed_process = subprocess.run(
            [
                "gitleaks-7.6.1",
                "--quiet",
                "--no-git",
                "--format=json",
                f"--config-path={self.patterns_path}",
                f"--path={self.test_pattern_dir}",
            ],
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed_process.stderr.decode("UTF-8"), "")

        raw_lines = completed_process.stdout.splitlines()
        leaks = [json.loads(line) for line in raw_lines]

        # These are the offenders found above. This will need to be updated
        # when adding a new item to test.
        matches = {(m["description"], m["offender"]) for m in SHOULD_MATCH}

        for leak in leaks:
            leak_key = (leak["rule"], leak["offender"])

            self.assertIn(leak_key, matches)
            matches.remove(leak_key)

        # Make sure everything's been accounted for
        self.assertEqual(matches, set())
