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

VERSION = "7.6.1"

SHOULD_MATCH = [
    *[
        {
            "description": "(File) General Secret",
            "example": f"{i}dyKPI359SlFVIEKoL9qakPlP5xuQDxZ9aGP45xAc5NI",
            "offender": f"{i}dyKPI359SlFVIEKoL9qakPlP5xuQDxZ9aGP45xAc5NI",
            "filename": f"foo.{ext}",
            "comment": "Some kind of secret file",
        }
        for i, ext in enumerate(
            (
                "clientSecret",
                "password",
                "sometoken",
            )
        )
    ],
    *[
        {
            "description": "General Secret",
            "example": f"{prefix}{password}{suffix} {notsecretformat}",
            "offender": f"{prefix}{password}{suffix}",
            "comment": "Test Genearl Secret with optional notsecret tag",
        }
        for prefix, suffix in (
            ("password = '", "'"),
            ("secret= '", "'"),
            ('secret_key": "', '"'),
            ('secret_access_key": "', '"'),
            ('secret_accesskey": "', '"'),
            ('SecretAccessKey": "', '"'),
            ("secret=", " "),
            ("api_key=", " "),
        )
        for (password, notsecretformat) in (
            (
                "swke6BX0-14v3rYb2Ix32AIfTh9j_H_671dcf8gjpdTbsThiJfxapnAqFs8_kiW4ME-ZPxLmVEgmTxxwlb8Xvw",
                "",
            ),
            # Invalid tag
            ("1b3d576ba5a108c3b7374142bfd02992", "notasecret"),
            # Doesn't start correctly
            ("2b3d576ba5a108c3b7374142bfd02992", "yonotsecret"),
            # Doesn't start correctly
            ("3b3d576ba5a108c3b7374142bfd02992", "'notsecret"),
            # Doesn't end correctly
            ("4b3d576ba5a108c3b7374142bfd02992", "notsecret'"),
            # Doesn't end correctly
            ("5b3d576ba5a108c3b7374142bfd02992", "notsecretyo"),
        )
    ],
    *[
        {
            "description": "ArgoCD JWT",
            "example": jwt,
            "offender": jwt,
            "comment": 'this searches for "iss":"argocd"',
        }
        for jwt in (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsZWFrdGsiLCJub3RlIjoiZm9yIHRlc3RpbmcgQXJnb0NEIG1hdGNoZXMiLCJ4IjoieHh4IiwiaXNzIjoiYXJnb2NkIn0.VJXhFqDs4FGGHPznFO8ZkwiteXL5sLMeUaGGEXS02h4",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsZWFrdGsiLCJub3RlIjoiZm9yIHRlc3RpbmcgQXJnb0NEIG1hdGNoZXMiLCJpc3MiOiJhcmdvY2QifQ.IMSC5Gl6CavUctOoILAcHN4YAsH3ihQz7l6mDobClXw",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsZWFrdGsiLCJub3RlIjoiZm9yIHRlc3RpbmcgQXJnb0NEIG1hdGNoZXMiLCJ4IjoieCIsImlzcyI6ImFyZ29jZCJ9.kHldeGEECY3basc-aTT-3eQvellg8T02h8M02M3v3c0",
        )
    ],
    *[
        {
            "description": "Kubernetes Service Account JWT",
            "example": jwt,
            "offender": jwt,
            "comment": 'this searches for "iss":"kubernetes/serviceaccount"',
        }
        for jwt in (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsZWFrdGsiLCJub3RlIjoiZm9yIHRlc3RpbmcgS3ViZSBTQSBtYXRjaGVzIiwieCI6IngiLCJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.5BTklQydvs6yaPgO6MJoSDk89wZjX8QMJ51m5bMCHx8",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsZWFrdGsiLCJub3RlIjoiZm9yIHRlc3RpbmcgS3ViZSBTQSBtYXRjaGVzIiwieCI6Inh4IiwiaXNzIjoia3ViZXJuZXRlcy9zZXJ2aWNlYWNjb3VudCJ9.t8R0N8jjMXv_4E9JKwGfJ5hrsO3del5oJpD6j66O-VU",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsZWFrdGsiLCJub3RlIjoiZm9yIHRlc3RpbmcgS3ViZSBTQSBtYXRjaGVzIiwieCI6Inh4eCIsImlzcyI6Imt1YmVybmV0ZXMvc2VydmljZWFjY291bnQifQ.JLGKRW3i-CMu5Y_p0y1cgNFokjyVJjs6zO3g_P5nawQ",
        )
    ],
    *[
        {
            "description": "(YAML) General Secret",
            "example": example,
            "offender": offender,
            "comment": "General secret tests for yaml rules",
            "filename": f"yaml-test.{ext}",
        }
        for (example, offender, ext) in (
            (
                "secret: /LNvEGXEXY9Bx/YNvE{asdf.YNvEGXEXY9BS}",
                "secret: /LNvEGXEXY9Bx/YNvE{asdf.YNvEGXEXY9BS}",
                "yml",
            ),
            (
                "secret: /XNvEGXEXY9B9/YNvEasdf.YNvEGXEXY9BS}",
                "secret: /XNvEGXEXY9B9/YNvEasdf.YNvEGXEXY9BS}",
                "yaml",
            ),
            (
                "secret-key: /GNvEGXElY9BS/YNvE:asdf.YNvEGXEXY9BS}",
                "secret-key: /GNvEGXElY9BS/YNvE:asdf.YNvEGXEXY9BS}",
                "yml",
            ),
            (
                "secretKey: /GNvEGXEXm9BS/YNvE:asdf.YNvEGXEXY9BS}",
                "secretKey: /GNvEGXEXm9BS/YNvE:asdf.YNvEGXEXY9BS}",
                "yaml",
            ),
            (
                "accessToken: /ANvEGX1XY9BS/YNvE:asdf.YNvEGXEXY9BS}",
                "Token: /ANvEGX1XY9BS/YNvE:asdf.YNvEGXEXY9BS}",
                "yml",
            ),
            (
                "clientSecret: /GNvEGgEXY9BS/YNvEasdf.YNvEGXEXY9BS}",
                "Secret: /GNvEGgEXY9BS/YNvEasdf.YNvEGXEXY9BS}",
                "yaml",
            ),
        )
    ],
    *[
        {
            "description": "Container Registry Authentication",
            "example": f"{q}{registry}{q}: {{ {q}auth{q}: {q}9ec7f53a0637bb3d78ab613e02014934{q} }}",
            "offender": f"{q}{registry}{q}: {{ {q}auth{q}: {q}9ec7f53a0637bb3d78ab613e02014934{q}",
            "comment": "Should capture in-line container registry secrets",
        }
        # Quote Type
        for q in (
            # Normal
            '"',
            # Escaped
            r"\"",
        )
        for registry in (
            "quay.io",
            "docker.io",
            "foo.bar.redhat.io",
            "foo.bar.redhat.com",
            "foo.bar.openshift.com",
            "foo.bar.openshift.io",
        )
    ],
    *[
        {
            "description": "Container Registry Authentication",
            "example": f"{prefix}{test_id}{value}{suffix}",
            "offender": f"{test_id}{value}",
            "comment": "Should capture encoded container registry secrets",
        }
        # The test_id keeps the matches from being exactly the same between tests
        for test_id, (prefix, suffix) in enumerate(
            (
                (".dockerconfigjson: ", ""),
                ('Data: "', '"'),
            )
        )
        for value in (
            "eyJhdXRocyI6IHsibG9jYWxob3N0IjogImF1dGgiOiAibXdhaGFoYWhhaGFoYWhhIn19Cg==",
            "eyJhdXRocyI6IHsiIjoge30sICJsb2NhbGhvc3QiOiAiYXV0aCI6ICJtd2FoYWhhaGFoYWhhaGEifX0K",
            "ZG9ja2VyY29uZmlnOiB7ImF1dGhzIjogeyIiOiB7fSwgImxvY2FsaG9zdCI6ICJhdXRoIjogIm13YWhhaGFoYWhhaGFoYSJ9fQo=",
            "YXsiYXV0aHMiOiB7IiI6IHt9LCAibG9jYWxob3N0IjogImF1dGgiOiAibXdhaGFoYWhhaGFoYWhhIn19Cg==",
            "YXsiYXV0aHMiOiBieyIiOiB7fSwgImxvY2FsaG9zdCI6ICJhdXRoIjogIm13YWhhaGFoYWhhaGFoYSJ9fQo=",
            "YTl7ImF1dGhzIjogYnsiIjoge30sICJsb2NhbGhvc3QiOiAiYXV0aCI6ICJtd2FoYWhhaGFoYWhhaGEifX0K",
            "MGE5eyJhdXRocyI6IGJ7IiI6IHt9LCAibG9jYWxob3N0IjogImF1dGgiOiAibXdhaGFoYWhhaGFoYWhhIn19Cg==",
            "MGE5eyJhdXRocyI6IGJ7IiI6IHt9LCAicmVkaGF0LmlvIjogImF1dGgiOiAibXdhaGFoYWhhaGFoYWhhIn19Cg==",
        )
    ],
    {
        "description": "Container Registry Authentication",
        "example": 'reg := registry.New("quay.io", "user", "09e25b6fc894c83868715a8cce1ba7d2") // remove later',
        "offender": 'registry.New("quay.io", "user", "09e25b6fc894c83868715a8cce1ba7d2")',
        "comment": "Should capture container registry passwords.",
    },
    {
        "description": "OpenShift Login Token",
        "example": "oc login --some-opt --token=sha256~CL9vOGM0koa67eipnogHwP6KmfeAOd6ZwMo88Qo3-Kw --foo --bar --baz",
        "offender": "oc login --some-opt --token=sha256~CL9vOGM0koa67eipnogHwP6KmfeAOd6ZwMo88Qo3-Kw",
        "comment": "Detect tokens for the OpenShift login command",
    },
    {
        "description": "General Secret",
        "example": "secret='/GNvEGXEXY9BS/YNvE:${asdf.YNvEGXEXY9BS}'",
        "offender": "secret='/GNvEGXEXY9BS/YNvE:${asdf.YNvEGXEXY9BS}'",
        "filename": "src/azure-cli/azure/cli/command_modules/aro/tests/latest/recordings/foo.yml",
        "comment": "Detect things in the aro module",
    },
    {
        "description": "General Secret",
        "example": "secret='/YNvEGXEXY9BS/YNvE:${asdf.YNvEGXEXY9BS}'",
        "offender": "secret='/YNvEGXEXY9BS/YNvE:${asdf.YNvEGXEXY9BS}'",
        "comment": "Even though this looks like it has a variable at the end, it still has a secret contained in it",
    },
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
        "description": "AWS IAM Unique Identifier",
        "example": "AWS_ACCESS_KEY=A3TGOBTGY4DIMRXMIYGE",
        "offender": "=A3TGOBTGY4DIMRXMIYGE",
        "comment": "Should capture aws access keys",
    },
    {
        "description": "AWS Secret Key",
        "example": "  AWSSecretKey=af60f112a534df0cc1e4d892b5768f3easefasza foo=bar",
        "offender": "AWSSecretKey=af60f112a534df0cc1e4d892b5768f3easefasza ",
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
        "offender": 'password": "3ae68d9f8ccfc898ee2555a5f8f228b9"',
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
        "offender": 'secret": "$A3ae68d9f8ccfc898ee2555a5f8f228b9"',
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
        "description": "Htpasswd File",
        "example": "bob123:$apr1$FaPYZHMz$jYiw5.ExmVKeLbjex5Jvr34uA/",
        "offender": "bob123:$apr1$FaPYZHMz$jYiw5.ExmVKeLbjex5Jvr34uA/",
        "comment": "Test to see that htpasswd files show up",
        "filename": "my-htpasswd-file",
    },
    {
        "description": "Htpasswd File",
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
        "description": "GitHub Fine-Grained Personal Access Token",
        "example": "<access-token>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</access-token>",
        "offender": "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",
        "comment": "See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats",
    },
    {
        "description": "GitHub Personal Access Token",
        "example": "<access-token>ghp_16C7e42F292c6912E7710c838347Ae178B4a</access-token>",
        "offender": "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats",
    },
    {
        "description": "GitHub OAuth Access Token",
        "example": "token='gho_16C7e42F292c6912E7710c838347Ae178B4a'",
        "offender": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats",
    },
    {
        "description": "GitHub User to Server Token",
        "example": "'gt-token': 'ghu_16C7e42F292c6912E7710c838347Ae178B4a'",
        "offender": "ghu_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats",
    },
    {
        "description": "GitHub Server to Server Token",
        "example": "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
        "offender": "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats",
    },
    {
        "description": "GitHub Refresh Token",
        "example": "ghr_16C7e42F292c6912E7710c838347Ae178B4a",
        "offender": "ghr_16C7e42F292c6912E7710c838347Ae178B4a",
        "comment": "See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats",
    },
    {
        "description": "GitLab Access Token",
        "example": "my_cred=glpat-LwnfdsSHX1aSGxsqsPUX",
        "offender": "glpat-LwnfdsSHX1aSGxsqsPUX",
        "comment": "From gitlab.com",
    },
    {
        "description": "GitLab Pipeline Trigger Token",
        "example": "trigger_sec=glptt-bcce2270d3c9c90c0a4320b6e8742fb450c27cc9",
        "offender": "glptt-bcce2270d3c9c90c0a4320b6e8742fb450c27cc9",
        "comment": "From gitlab.com",
    },
    {
        "description": "GitLab Runner Registration Token",
        "example": "runner_sec=glrt-64NXmvdxFL_9cliRha7y",
        "offender": "glrt-64NXmvdxFL_9cliRha7y",
        "comment": "From gitlab.com",
    },
    {
        "description": "GitLab Runner Registration Token",
        "example": "runner_sec=GR134894164NXmvdxFL_9cliRha7y",
        "offender": "GR134894164NXmvdxFL_9cliRha7y",
        "comment": "From gitlab.com",
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
        "description": "URL User and Password",
        "example": "http://username:1d902de68e4113f5855a6c88314cec6a@host/foo/bar/baz",
        "offender": "://username:1d902de68e4113f5855a6c88314cec6a@host",
        "comment": "Should capture basic auth for http",
    },
    {
        "description": "URL User and Password",
        "example": "https://username:2d902de68e4113f5855a6c88314cec6a@host",
        "offender": "://username:2d902de68e4113f5855a6c88314cec6a@host",
        "comment": "Should capture basic auth for https",
    },
    {
        "description": "URL User and Password",
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
]

SHOULD_NOT_MATCH = [
    *[
        {
            "example": example,
            "comment": ".gitleaks realated config",
            "filename": filename,
        }
        for example, filename in (
            (
                'secret_key = "gl-test-766a929d93c9ef30ce3d72d6384eb6fa"',
                ".gitleaks.toml",
            ),
            (
                'secret_key = "gl-test-866a929d93c9ef30ce3d72d6384eb6fa"',
                ".gitleaks/baseline.json",
            ),
            (
                'secret_key = "gl-test-966a929d93c9ef30ce3d72d6384eb6fa"',
                ".gitleaksignore",
            ),
        )
    ],
    *[
        {
            "example": example,
            "comment": "placeholder value",
            "filename": "yaml-test.yaml",
        }
        for example in (
            r"secret: auth-test-password",
            r"secret: <PLACEHOLDER>",
            r"secret: @@PLACEHOLDER@@",
            r"secret: %PLACEHOLDER%",
            r"secret: $PLACEHOLDER$",
            r"secret: __PLACEHOLDER__",
            r"secret: _PLACEHOLDER_",
            r"secret: ALL_UPPER_LETTERS_OR_UNDERSCORS",
            r"secret: {PLACEHOLDER}",
            r"secret: ${PLACEHOLDER}",
            r"secret: %{PLACEHOLDER}",
            r"secret: update-your-postgres-pass-here # a common placeholder setup",
            r"secret: Some...placeholder",
            r"secret: [%PLACEHOLDER%]",
            r"secret: [PLACEHOLDER]",
            r"secret: $(ls -l abcedafaca;lkj;lk)",
            r"secret: \$(ls -l aclkaj;ria;ka;ek;jrakj)",
            r"secret: SOME_CONSTANT_PREFIX_${PLACEHOLDER}",
            r"secret: /SOME/path:${PLACEHOLDER}",
            r"secret: $SOME_ENV_VARIABLE-optional-text",
            r"secret: \$SOME_ENV_VARIABLE-optional-text",
            # Contains EXAMPLE base64 encoded in it
            "secret: 377gjPEd3Wvo+3ojeGiknEVYQU1QTEUKRVhBTVBMRQo=",
            # Reference and not a secret itself
            "secret: sshPrivateKey",
            # Has spaces
            "secret: foo bar baz",
        )
    ],
    *[
        {
            "example": f"-----BEGIN {key_type} PRIVATE KEY-----",
            "comment": "Should ignore based on the filename",
            "filename": filename,
        }
        for key_type in ["EC", "PGP", "DSA", "RSA", "OPENSSH"]
        for filename in [
            "some.test.ecdsa_key",
            "diff/usr/lib64/libssh.so.4.8.7",
            "diff/usr/share/mime/magic",
            "diff/usr/share/mime/mime.cache",
            "diff/usr/share/mime/packages/freedesktop.org.xml",
            "diff/usr/share/misc/magic.mgc",
            "dummy.key",
            "dummy.pem",
            "foo/bar/bin/ssh-add",
            "foo/bar/usr/bin/ssh",
            "foo/usr/libexec/cockpit-certificate-ensure",
            "lib64/libgnutls.so.30.30.0",
            "src/ukify/test/example.signing.key",
            "test/recipes/30-test_evp_data/evppkey_rsa_common.pem",
            "test/recipes/30-test_evp_data/evppkey_rsa_common.txt",
            "test/smime-certs/smrsa1024.pem",
            "test/smime-certs/smrsa1024.der",
            "test/smime-certs/smrsa1024.key",
            "test/testec-p112r1.pem",
            "usr/libexec/openssh/ssh-keysign",
            "usr/libexec/openssh/ssh-pkcs11-helper",
            "usr/sbin/sshd",
            "usr/share/mime/magic",
            "usr/share/mime/mime.cache",
            "usr/share/mime/packages/freedesktop.org.xml",
        ]
    ],
    *[
        {
            "example": f"{keyword}='{value}'",
            "comment": "Likely encrypted values",
        }
        for keyword in ("secret", "secret_key", "password")
        for value in [
            "ENC[RSA,tUf83Ex0oSbDGa8vaU1hGqesODG9J4j40EgLClQYrwNT]",
            "RU5DW1JTQSx0VWY4M0V4MG9TYkRHYTh2YVUxaEdxZXNPREc5SjRqNDBFZ0xDbFFZcndOVF0=",
            "ENC[AES256_GCM,tUf83Ex0oSbDGa8vaU1hGqesODG9J4j40EgLClQYrwNT]",
            "RU5DW0FFUzI1Nl9HQ00sdFVmODNFeDBvU2JER2E4dmFVMWhHcWVzT0RHOUo0ajQwRWdMQ2xRWXJ3TlRd",
        ]
    ],
    *[
        {
            "example": f"scheme://user:{password}@localhost:443",
            "comment": "URL default passwords or placeholders",
        }
        for password in [
            "$(TOKEN)",
            "$TOKEN",
            "$encrypted$",
            "${TOKEN}",
            "%q",
            "&lt;password&gt;",
            "[TOKEN]",
            "\${GHTOKEN}",
            "__MONGO_PASSWORD__",
            "candlepin",
            "default",
            "keylime",
            "password",
            "password-foo-bar-baz",
            "postgres",
            "prisma",
            "rabbitmq",
            "redhat",
            "some-placeholder-token",
            "userpass",
            "{TOKEN}",
            '"$TOKEN"',
        ]
    ],
    *[
        {
            "example": example,
            "comment": "General Secret placeholder or non-secret value",
            "filename": filename,
        }
        for filename in (
            "some.yaml",
            "specs/github.json",
            "some-file",
        )
        for prefix, suffix, is_xml in (
            ("secret='", "'", False),
            ("secret:'", "'", False),
            ("'secret':'", "'", False),
            ("password='", "'", False),
            ("PASSWORD='", "'", False),
            ("secret_key='", "'", False),
            ("SECRET_KEY='", "'", False),
            ("secret-key='", "'", False),
            ('imagePullSecret="', '"', False),
            ("secretkey='", "'", False),
            ("secretkey='", "', some = 'other value'", False),
            ("secret_access_key='", "'", False),
            ('Path to Secret: "', '"', False),
            ('"secret": "', '"', False),
            ('"password": "', '"', False),
            ("<password>", "</", True),
            ("<secret>", "</", True),
            ('<FooSecret id="new">', "</", True),
        )
        for example, also_test_xml in (
            (f"{prefix}{suffix}", True),
            (f"{prefix}auth-test-password{suffix}", True),
            (f"{prefix}<PASSWORD_PLACEHOLDER_123>{suffix}", True),
            (f"{prefix}@@PASSWORD_PLACEHOLDER_123@@{suffix}", True),
            (f"{prefix}@@FILE:/some/file/path@@{suffix}", True),
            (f"{prefix}%PASSWORD_PLACEHOLDER_123%{suffix}", True),
            (f"{prefix}$PASSWORD_PLACEHOLDER_123${suffix}", True),
            (f"{prefix}__GITLAB_OAUTH_SECRET__{suffix}", True),
            (f"{prefix}_GITLAB_OAUTH_SECRET_{suffix}", True),
            (f"{prefix}ALL_UPPER_LETTERS_OR_UNDERSCORS{suffix}", True),
            (f"{prefix}$(PASSWORD_PLACEHOLDER_123){suffix},", True),
            (f"{prefix}{{PASSWORD_PLACEHOLDER_123}}{suffix}", True),
            (f"{prefix}${{PASSWORD_PLACEHOLDER_123}}{suffix}", True),
            (f"{prefix}%{{PLACEHOLDER}}{suffix}", True),
            (
                f"{prefix}update-your-postgres-pass-here # a common placeholder setup{suffix}",
                True,
            ),
            (f"{prefix}Some...placeholder{suffix}", True),
            (f"{prefix}[%PASSWORD_PLACEHOLDER_123%]{suffix}", True),
            (f"{prefix}[SOME_RANDOM_SECRET]{suffix}", True),
            (f"{prefix}$(ls -l abcedafaca;lkj;lk){suffix}", True),
            (f"{prefix}\\$(ls -l aclkaj;ria;ka;ek;jrakj){suffix}", True),
            (f"{prefix}SOME_CONSTANT_PREFIX_${{PLACEHOLDER}}{suffix}", True),
            (f"{prefix}/SOME/path:${{PLACEHOLDER}}{suffix}", True),
            (f"{prefix}$SOME_ENV_VARIABLE-optional-text{suffix}", True),
            (f"{prefix}\\$SOME_ENV_VARIABLE-optional-text{suffix}", True),
            (f"{prefix}rescue_disk_ephemeral_encryption_secret_uuid{suffix}", True),
            (f"{prefix}data/my_root/my_folder{suffix}", True),
            (f"{prefix}27BZdTpuIl9u...pE+SpU4C2vQSY={suffix}", True),
            (f"{prefix}APPLICATION_RESOURCES{suffix}", True),
            (f"{prefix}http://secret_dsn{suffix}", True),
            (f"{prefix}/etc/app-settings/password-file{suffix}", True),
            (f"{prefix}YOURGENERATEDAPPLICATIONPASSWORD{suffix}", True),
            (
                f"{prefix}{{{{ lookup('hashi_vault', 'secret=kv/foo:username token={{{{ token_var }}}} url=http://host:8200')}}}}{suffix}",
                True,
            ),
            (f"{prefix}`kubectl get`{suffix}", True),
            (f"{prefix}FIXME!px1{suffix}", True),
            (f"{prefix}PW_PLACEHOLDER{suffix}", True),
            (f"{prefix}FAKE.thing(){suffix}", True),
            # Contains EXAMPLE in base64
            (
                f"{prefix}RVhBTVBMRWlpdVdSRUhGY3JISTN6SzBMZGVub1Avc0tmOW9aejhhbXYyY29rNlBja1E9Cg=={suffix}",
                True,
            ),
            (f"{prefix}USER_PASSWORD,{suffix}", True),
            (f"{prefix}foo/bar.baz.yaml.tmpl{suffix}", True),
            # Password in spanish True),
            (f"{prefix}Contrase\\u00f1a{suffix}", True),
            (f'{prefix}some.property.password="$SOME_PASSWORD_VARIABLE"{suffix}', True),
            (f"{prefix}ONLYFORDEVELOPMENT{suffix}", True),
            (
                f"{prefix}for-cicd-${{some.placeholder.VALUE_REF}}${{some.placeholder.VALUE_REF}}{suffix}",
                True,
            ),
            (f"{prefix}$Abc12345678{suffix}", True),
            (f"{prefix}$CREDENTIAL_PLACEHOLDER${suffix}", True),
            (f"{prefix}\\u201cfakepasswd#\\u201d{suffix}", True),
            (f"{prefix}DEFAULT_APP_SECRET_DEFAULT{suffix}", True),
            (
                f"{prefix}vFWYcZmbFsDXW+JvMoZyttVkAE+ZXEpqxrCv0t86pgolDS/UWncEeUtz/lsjLh54wN1j3SBKmIPSbq/VOaSFBg=={suffix} # noqa: E501",
                True,
            ),
            (
                f"{prefix}vFWYcZmbFsDXW+JvMoZyttVkAE+ZXEpqxrCv0t86pgolDS/UWncEeUtz/lsjLh54wN1j3SBKmIPSbq/VOaSFB9=={suffix} # nosec",
                True,
            ),
            (
                f"{prefix}vFWYcZmbFsDXW+JvMoZyttVkAE+ZXEpqxrCv0t86pgolDS/UWncEeUtz/lsjLh54wN1j3SBKmIPSbq/VOaSFB8=={suffix} # gitleaks:allow",
                True,
            ),
            (
                f"{prefix}vFWYcZmbFsDXW+JvMoZyttVkAE+ZXEpqxrCv0t86pgolDS/UWncEeUtz/lsjLh54wN1j3SBKmIPSbq/VOaSFB7=={suffix} # notsecret ",
                True,
            ),
            (
                f"{prefix}vFWYcZmbFsDXW+JvMoZyttVkAE+ZXEpqxrCv0t86pgolDS/UWncEeUtz/lsjLh54wN1j3SBKmIPSbq/VOaSFB5=={suffix} #notsecret ",
                True,
            ),
            (
                f"{prefix}vFWYcZmbFsDXW+JvMoZyttVkAE+ZXEpqxrCv0t86pgolDS/UWncEeUtz/lsjLh54wN1j3SBKmIPSbq/VOaSFB4=={suffix} //notsecret ",
                True,
            ),
            (
                f"{prefix}vFWYcZmbFsDXW+JvMoZyttVkAE+ZXEpqxrCv0t86pgolDS/UWncEeUtz/lsjLh54wN1j3SBKmIPSbq/VOaSFB3=={suffix} # notsecret - this is a false positive",
                True,
            ),
            (
                f"{prefix}vFWYcZmbFsDXW+JvMoZyttVkAE+ZXEpqxrCv0t86pgolDS/UWncEeUtz/lsjLh54wN1j3SBKmIPSbq/VOaSFB2=={suffix} notsecret ",
                True,
            ),
            (f"{prefix}/some/Path:${{foo.bar.baz}}{suffix}", True),
            (f"{prefix}/tmp/${{pull_secret_filename}}{suffix}", True),
            (f"{prefix}spec.some.path[*].secretRef{suffix}", True),
            (f"{prefix}&lt;password_for_some_account&gt;{suffix}", True),
            (f"{prefix}00000000-0000-0000-0000-000000000000{suffix}", True),
            (f"{prefix}true|false{suffix}", True),
            (f"{prefix}\\$KUBEADMIN_PASS{suffix}", True),
            (f"{prefix}PROVIDE-A-PASSWORD-SALT{suffix}", True),
            (f"{prefix}NamespaceOpenshiftResourceVaultSecret_v1{suffix}", True),
            (f'{prefix}"&secretKey=RAW(" + s3_secretKey + ")"{suffix}', True),
            (f"{prefix}some-secret-CHANGEME{suffix}", True),
            (f"{prefix}GITHUB_TOKEN=${{GITHUB_TOKEN}}{suffix}", True),
            (
                f'{prefix}$(KUBECONFIG="$target" kubectl get sa "$sa" -n "$namespace" -o json |{suffix}',
                True,
            ),
            (f"{prefix}[[.Some.Build.Secret]]{suffix}", True),
            (f"{prefix}\(password){suffix}", True),
            (f"{prefix}#{{password}}{suffix}", True),
            (f"{prefix}#{{password}}{suffix}", True),
            (f"{prefix}`generate-password`{suffix}", True),
            (f"{prefix}#REPLACE_ME#{suffix}", True),
            (f"{prefix}${{PASSWORD_PLACEHOLDER_123}}{suffix}", True),
            (f"{prefix}SuperSecretPassword!{suffix}", True),
            (
                f"{prefix}#{{File.exists?('/some/path') ? open('/some/path','r') do |f|f.read end : ''}}{suffix}",
                True,
            ),
            (f"{prefix}example-9b5a699bc0dc8211f103a9a305b01a51{suffix}", True),
            (f"{prefix}quickstart-9b5a699bc0dc8211f103a9a305b01a51{suffix}", True),
            (f"{prefix}9b5a699bc0dc8211f103a9a305b01a51-example{suffix}", True),
            (f"{prefix}path={{.spec.databasePassword}}{suffix}", True),
            (f"{prefix}samplepwd{suffix}", True),
            (f"{prefix}the-thing-is-required{suffix}", True),
            (f"{prefix}update-your-postgres-pass-here{suffix}", True),
            (f"{prefix}autogenerated_stuff{suffix}", True),
            (f"{prefix}this-is-not-real!{suffix}", True),
            (f"{prefix}NotActuallyApplied!{suffix}", True),
            (f"{prefix}ADMIN_PASSWORD_HERE!{suffix}", True),
            (f"{prefix}\$(POSTGRESQL_PASSWORD){suffix}", True),
            (f'{prefix}+privateDataPlaceholder()+"&{suffix}', True),
            (f"{prefix}foo{suffix}", True),
            (f"{prefix}.odc-multiple-key-selector button{suffix}", True),
            (f"{prefix}, listKeys(resourceId({suffix}", True),
            (f'{prefix}exp_password" or "{{{{ example_password }}}}{suffix}', True),
            (f"{prefix}secret12345{suffix}", True),
            (f"{prefix}password_to_replace{suffix}", True),
            (f"{prefix}some_placeholder_passwd{suffix}", True),
            (f"{prefix}some_placeholder_pwd{suffix}", True),
            (f"{prefix}some_placeholder-pwd{suffix}", True),
            (f"{prefix}passwort_to_replace{suffix}", True),
            (f"{prefix}passord_to_replace{suffix}", True),
            (f"{prefix}base64string{suffix}", True),
            (f"{prefix}GITHUB_ACCESS_TOKEN{suffix}", True),
            (f"{prefix}foo_client_id{suffix}", True),
            (f"{prefix}foo_key_private{suffix}", True),
            (f"{prefix}%{{pull_secret}}{suffix}", True),
            (
                f"{prefix}HFYp7dGQhQ7G03juqw373JlSw8K/K7MDENG/bPxRfiCY{suffix} //nolint:gosec",
                True,
            ),
            (f"{prefix}HFYp7dGQhQ7G03juqw373JlSw8K/K7MDENG/EXAMPLEKEY{suffix}", True),
            (f"{prefix}$SOME_ENV_VAR-value{suffix}", True),
            (f"{prefix}c007cd12-1fe7-4843-947e-ddecfc0d8913{suffix}", True),
            (f"{prefix}${{SESSION_SECRET}}={suffix}", False),
            (f"{prefix}abcdef0123456789{suffix}", True),
            (f"{prefix}foo-credentials{suffix}", True),
            (f"{prefix}k8s-infra-key{suffix}", True),
            (f"{prefix}insert user Secret{suffix}", True),
            (f"{prefix}please-insert-abc123-Secret{suffix}", True),
            (f"{prefix}adfasdfasdfadfa-abc123.json{suffix}", True),
            (f"{prefix}adfasdfasdfadfa-abc123-data{suffix}", True),
            (f"{prefix}adfasdfasdfadfa-abc123-kubeconfig{suffix}", True),
            (f"{prefix}please-insert-abc123.Secret{suffix}", True),
            (f"{prefix}secret{suffix}", True),
            (f"{prefix}secret_to_replace{suffix}", True),
            (f"{prefix}password{suffix}", True),
            (f"{prefix}password_to_replace{suffix}", True),
            (f"{prefix}client-secret-for-service-principal{suffix}", True),
            (f"{prefix}SUPER-SECRET-123{suffix}", True),
            (f"{prefix}insert-user-PasSworD{suffix}", True),
            (f"{prefix}awx-postgres-configuration{suffix}", True),
            (f"{prefix}multicluster-mongodb-client-cert{suffix}", True),
            (f"{prefix}multicluster-mongodb-client-certification{suffix}", True),
            (f"{prefix}multicluster-mongodb-client-auth{suffix}", True),
            (f"{prefix}multicluster-mongodb-client-authentication{suffix}", True),
            (f"{prefix}reposure-registry{suffix}", True),
            (f"{prefix}reposure-registry-secrets{suffix}", True),
            (f"{prefix}foobar{suffix}", True),
            (f"{prefix}/var/run/secret/secret.yml{suffix}", True),
            (f"{prefix}),d?_.a.createElement({suffix}", False),
            (f"{prefix}).append(toIndentedString(password)).append({suffix}", False),
            (
                f"{prefix}django-insecure-zeu#xlk35rk7$b0o_hg7bfr@60A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS{suffix}",
                True,
            ),
            (f"{prefix}material/form-textbox-password.svg{suffix}", True),
            (f"{prefix}material/form-textbox-password.png{suffix}", True),
            (f"{prefix}material/form-textbox-password.jpeg{suffix}", True),
            (f"{prefix}material/form-textbox-password.txt{suffix}", True),
            # make sure lower case with dashes is NOT caught
            (f"{prefix}lol-ikr-those-kids-r-krazy{suffix}", False),
            # some numbers and upper case are fine as long as a good portion is lower with dashes
            (f"{prefix}K8s-lol-ikr-those-kids-r-krazy{suffix}", False),
            (
                f"{prefix}/run/kubernetes/secrets/oscontainer-registry/dockercfg{suffix}",
                True,
            ),
            (
                f"{prefix}/var/run/secrets/atomic-reactor/v2-registry-dockercfg{suffix}",
                True,
            ),
            (f"{prefix}/path/to/password/file{suffix}", True),
            (f"{prefix}ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx{suffix}", True),
            (f"{prefix}ghp_************************************{suffix}", True),
            (f"{prefix}ghp_....................................{suffix}", True),
            (f"{prefix}$(openssl rand -hex 16){suffix}", True),
            (f"{prefix}SOME_PREFIX_WITH_A_${{variable}}{suffix}", True),
            (f"{prefix}placeholder-password.12345{suffix}", True),
            (f"{prefix}SomeSecretPassw0rd{suffix}", True),
            (f"{prefix}https://www.example.com{suffix}", True),
            (f"{prefix}\\u003cpassword\\u003e{suffix}", True),
            (f"{prefix}SomeOldSecretKey{suffix}", True),
            (f"{prefix}db-fields-encryption{suffix}", True),
            (f"{prefix}/acaial39ama-agent.conf{suffix}", True),
            (f"{prefix}/acaial39ama-agent.json{suffix}", True),
            (f"{prefix}/acaial39ama-agent.yaml{suffix}", True),
            (f"{prefix}NewPassword123{suffix}", True),
            (f"{prefix}NewPassword1234{suffix}", True),
            (f"{prefix}SomeClientSecretYo{suffix}", False),
            (f"{prefix}some-client-secret-yo{suffix}", False),
            (f"{prefix}0xrMXdwXLB89EXAMPLELL82G3GC212lnGI{suffix}", False),
            # Common ansible placeholder from the docs
            (f"{prefix}GoodNewsEveryone{suffix}", False),
            (f"{prefix}'$SOME_PASSWORD'{suffix}", False),
            (f"{prefix}$(params.SOME_PASSWORD){suffix}", True),
        )
        if not is_xml or is_xml and also_test_xml
    ],
    *[
        {
            "example": example,
            "comment": "FP/Placeholder in URL User and Password",
        }
        for example in (
            "https?://_<username>_[:_<password>_]@_<hostname>_/_<path>_",
            "https://f4c38c5:$githubpac@github.com",
            "https://f4c38c5:27BZdTpuIl9u...pE+SpU4C2vQSY=@github.com",
            "http://username:pGeGXSEFgGSogv48jcTFaJip@ip:port",
            "http://username:pGeGXSEFgGSogv48jcTFaJip@example.com",
            "https://test:adfa;dkj;aek;j@example.com",
            "https://test:adfa;dkj;aek;j@git.example.com",
            "https://examle.com/foo:current@Cacheable",
            "http://some-host:8080,org.java.stuff@1fc032aa",
        )
    ],
    *[
        {
            "example": example,
            "comment": "Wordpress placeholder values",
        }
        for example in (
            "define('AUTH_KEY', '${AUTH_KEY}');",
            "define('AUTH_KEY', '{{AUTH_KEY}}');",
            "define('AUTH_KEY', '$WP_AUTH_KEY');",
            "define('SECURE_AUTH_KEY', '$WP_SECURE_AUTH_KEY');",
            "define('LOGGED_IN_KEY', '$WP_LOGGED_IN_KEY');",
            "define('NONCE_KEY', '$WP_NONCE_KEY');",
            "define('AUTH_SALT', '$WP_AUTH_SALT');",
            "define('SECURE_AUTH_SALT', '$WP_SECURE_AUTH_SALT');",
            "define('LOGGED_IN_SALT', '$WP_LOGGED_IN_SALT');",
            "define('NONCE_SALT', '$WP_NONCE_SALT');",
        )
    ],
    {
        "example": '"example.com": { "auth": "9ec7f53a0637bb3d78ab613e02014934" }',
        "comment": "Container Auth: Should not capture domains we don't care about",
    },
    {
        "example": '{"auths":{"cloud.openshift.com":{"auth":"TJpnU0y1pDBkEKTcwzSAaoNV3jmkZz66LM4Jd6EBx0I.....TJpnU0y1pDBkEKTcwzSAaoNV3jmkZz66LM4Jd6EBx0I==","email":"user@example.com"},"quay.io":{"auth":"TJpnU0y1pDBkEKTcwzSAaoNV3jmkZz66LM4Jd6EBx0INo...","email":"user@example.com"},"',
        "comment": "redacted container registry auth",
    },
    {
        "example": "<password><![CDATA[${password}]]></password>",
        "comment": "placeholder wrappet in cdata tags",
    },
    {
        "example": "password=V1tXb7WBGlKIVAWqGw==",
        "comment": "Should ignore based on the filename",
        "filename": "foo/libexec/sudo/sudoers.so",
    },
    {
        "example": "<Password>$SomePlaceholderForAdminPassword$</Password>",
        "comment": "Placeholder",
    },
    {
        "example": "<Password><![CDATA[$SomePlaceholderForAdminPassword$]]></Password>",
        "comment": "Placeholder",
    },
    {
        "example": 'if (privateKey === "-----BEGIN RSA PRIVATE KEY-----") {',
        "comment": "This is just code looking for headers",
    },
    {
        "example": 'where("-----BEGIN RSA PRIVATE KEY-----")',
        "comment": "This is just code looking for headers",
    },
    {
        "example": "-----BEGIN PRIVATE KEY-----*******************************************************************************-----END PRIVATE KEY-----",
        "comment": "Redacted value",
    },
    {
        "example": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBg...W17oy4Qgj7OLNB\\n-----END PRIVATE",
        "comment": "Redacted value",
    },
    {
        "example": "bob123:$apr1$FaPYZHMz$jYiw5.ExmVKeLbjex5Jvr34uA/",
        "comment": "Data in a is skipped due to high FP rate",
        "filename": "htpasswd.md",
    },
    {
        "example": '{"version":8,"file":"htpasswd-chunk.min.js","sources":["webpack:///htpasswd-chunk.min.js"],"mappings":"AAAA","sourceRoot":""}',
        "comment": "Not a htpassword file",
        "filename": "htpasswd-page.js.map",
    },
    {
        "example": 'jq -rj \'"password: ",.some_password,"\\n"\'',
        "comment": "Part of a jq lookup",
    },
    {
        "example": "AWS_SECRET_ACCESS_KEY: RVhBTVBMRWlpdVdSRUhGY3JISTN6SzBMZGVub1Avc0tmOW9aejhhbXYyY29rNlBja1E9Cg==",
        "comment": "Contains EXAMPLE base64 encoded",
    },
    {
        "example": "Sample:<pre>AGPAIDCX94X8GQXML0OX</pre>",
        "comment": "Ignore AWS access keys marked as samples",
    },
    {
        "example": "YCu38AvUpJs01zHxja7Z9qhZWVAfjxP5H/A3TE8SENGWR1ZFQ206BR+Q06phGgStkRWAHCQ",
        "comment": "Contains something that looks like an AWS access key",
    },
    {
        "example": 'https://some.testing.server:443".\\u0000[xxx\\r\\n[user@host',
        "comment": "Contains a host later on so it looks like basic auth",
    },
    {
        "example": "fake_cert = '-----BEGIN OPENSSH PRIVATE KEY-----",
        "comment": "Test Cert",
    },
    {
        "example": "exampleCert = '-----BEGIN PRIVATE KEY-----",
        "comment": "Test Cert",
    },
    {
        "example": "testCert = '-----BEGIN RSA PRIVATE KEY-----",
        "comment": "Test Cert",
    },
    {
        "example": '"secret": "__GITLAB_OAUTH_SECRET__"',
        "comment": "These are placeholder values",
    },
    {
        "example": "@aws-cdk/aws-ecs:disableExplicitDeploymentControllerForCircuitBreaker",
        "comment": "This is code",
    },
    {
        "example": '"smtpSecret": "INSTALLATION_PREFIX-smtp",',
        "comment": "Placeholder value",
    },
    {
        "example": "@aws-cdk/aws-codepipeline:crossAccountKeyAliasStackSafeResourceName",
        "comment": "This is code",
    },
    {
        "example": "https://s3.amazonaws.com/examplebucket/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=A3TGOBTGY4DIMRXMIYGE/20130721/us-east-1/s3/aws4_request&X-Amz-Date=20130721T201207Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=%3Csignature-value%3E",
        "comment": "This is a presigned AWS URL",
    },
    {
        "example": 'awslb/podsvc.yaml": testExtendedTestdataRouterAwslbPodsvcYaml',
        "comment": "Looks similar to a AWS secret key",
    },
    {
        "example": " Af80f1/2+53=df0xc1e/d892b5768f3easefasz= ",
        "comment": "Avoid matching things ending with = due to the high FP count",
    },
    {
        "example": 'jq \'.spec.identityProviders += [{"htpasswd":{"fileData":{"name":"htpass-secret"}}...',
        "filename": "htpasswd-commands.sh",
        "comment": "Not a htpasswd match",
    },
    {
        "example": "AWS_ACCESS_KEY=A3TGOBTGY4DIMRXMIYGE #gitleaks:allow",
        "comment": "Allowed by gitleaks:allow",
    },
    {
        "example": "AWS_ACCESS_KEY=A3TGOBTGY4DIMRXMIYGE // gitleaks:allow",
        "comment": "Allowed by gitleaks:allow different comment type",
    },
    {
        "example": "WithSG.InterfacePropertiesFormat.IPConfigurations",
        "comment": "Looks really close to a SendGrid API Key's format",
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
        "example": " b/drivers/media/platform/bcm2835/Kconfig",
        "comment": "Meets the criteria for a potential aws secret key",
    },
    {
        "example": "# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)",
        "comment": "comment in a htpasswd file",
        "filename": "foo.htpasswd",
    },
    {
        "example": "asdfasdfaeaAIzaOObST8cGSeh3cYNvEGXEXY9BShQx1EtRdfZasdfasmlajasdfasdfasdf",
        "comment": "contains a substring that looks like a google api key",
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
        "example": 'cps.Data["metadata"] = []byte("password: " + tokenValue + "\nusername: NEW_VALUE")',
        "comment": "placeholder value",
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
        "example": "<UserSecretsId>c007cd12-1fe7-4843-947e-ddecfc0d8913</UserSecretsId>",
        "comment": "UUID should not be matched",
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
        "example": "bob123:example",
        "comment": "Should be too low-entropy",
        "filename": "my-htpasswd-file",
    },
    {
        "example": "user456:$jhI1AC9LG01KrQS$FzPCZHMe$jXiw5.8UevKx29pRH4AsT/",
        "comment": "Should not match because it's not in a htpasswd file",
    },
    {
        "example": "_Somef0lder/or/Somepath/that0snotakeyyepa.sh",
        "comment": "this is close to the regex for an aws key",
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
        "example": 'Password = "$A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS"',
        "comment": "Ignore general secrets in portions of the azure-cli repo",
        "filename": "src/azure-cli/azure/cli/command_modules/appservice/tests/latest/recordings/foo.yml",
    },
    {
        "example": 'secret = "$A3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS", some = "other value"',
        "comment": "Ignore general secrets in portions of the azure-cli repo",
        "filename": "src/azure-cli/azure/cli/command_modules/appservice/tests/latest/recordings/foo.yml",
    },
    {
        "example": '"hashed_secret": "972edb79d7c2e4374689572fb6c4ee7b",',
        "comment": "Ignore .secrets.baseline files",
        "filename": ".secrets.baseline",
    },
    {
        "example": 'secret="bf440e4268dA3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS"',
        "comment": "Ignore quickstarts",
        "filename": "foo/quarkus-quickstarts/bar/secret.txt",
    },
    {
        "example": 'secret="bf440e4268dA3QuDLm2Ukhsae68d9f8ccjhI1AC9LG01KrQS"',
        "comment": "Ignore testdata files",
        "filename": "foo/testdata/bar/secret.txt",
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
        "example": "define('DB_PASSWORD', 'password');",
        "comment": "Placeholder value for wordpress passwords",
    },
    {
        "example": "GITHUB_PERSONAL_ACCESS_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "comment": "Placeholder value for an Access Token",
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
        "example": "os_password=sys.argv[3]",
        "comment": "from code",
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
        "example": "password=&#34;placeholder&#34;,",
        "comment": "ignore likely documentation",
    },
    {
        "example": "password=\\u0026#34;placeholder&#34;,",
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
        "example": "password=\$MIRROR_OS_PASS&#34;",
        "comment": "Placeholder",
    },
    {
        "example": "password===this.options.password}var",
        "comment": "Just a comparison",
    },
    {
        "example": "secret=@(some_client_secret)",
        "comment": "Secret placeholder",
    },
    {
        "example": "secret=/data/stuff.auth",
        "comment": "Secret placeholder",
    },
    {
        "example": "PASSWORD=${DatabasePassword:?",
        "comment": "Secret placeholder",
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
]


class TestGitLeaks(TestCase):
    test_dir = Path(__file__).resolve().parent
    patterns_path = test_dir.joinpath(
        "..",
        "..",
        "..",
        "target",
        "patterns",
        "gitleaks",
        VERSION,
    )
    maxDiff = 10000

    def setUp(self):
        self.test_pattern_dir = Path(f"/tmp/leaktk-patterns-{VERSION}")

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
                f"gitleaks-{VERSION}",
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
