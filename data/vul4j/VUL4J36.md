# VUL4J-36: why it is not graded

VUL4J-36 (Apache Tika, CVE-2018-8017) is in the 42-entry subset but is not
graded. Its baseline status is `compile_failed_original`. This records why, and
what would have to change to bring it back.

## What happens

`tika-parsers/pom.xml` carries a profile that activates on a missing file:

```xml
<profile><id>testSetup</id>
  <activation><file><missing>
    ${basedir}/src/test/resources/org/apache/tika/parser/ner/opennlp/ner-person.bin
  </missing></file></activation>
```

When it activates, `ModelGetter.groovy` downloads nine model files. Seven come
from `opennlp.sourceforge.net/models-1.5`, which no longer serves them:

| requested URL | arrives as | what the server answers |
| --- | --- | --- |
| `http://opennlp.sourceforge.net/models-1.5/en-ner-person.bin` | `ner-person.bin` | 301 → https → 404 |
| `.../en-ner-location.bin` | `ner-location.bin` | 301 → https → 404 |
| `.../en-ner-organization.bin` | `ner-organization.bin` | 301 → https → 404 |
| `.../en-pos-maxent.bin` | `en-pos-maxent.bin` | 301 → https → 404 |
| `.../en-sent.bin` | `en-sent.bin` | 301 → https → 404 |
| `.../en-token.bin` | `en-token.bin` | 301 → https → 404 |
| `.../en-ner-date.bin` | `ner-date.bin` | 301 → https → 404 |
| `https://raw.githubusercontent.com/USCDataScience/AgePredictor/master/model/classify-bigram.bin` | `classify-bigram.bin` | 200, 61,951,098 bytes |
| `https://raw.githubusercontent.com/USCDataScience/AgePredictor/master/model/regression-global.bin` | `regression-global.bin` | 200, 886,072 bytes |

The two bodies the dead URLs return, measured 2026-11-04 from inside the
grading image:

| body | bytes | sha256 |
| --- | --- | --- |
| the `http` 301 page | 167 | `446a6087825fa73eadb045e5a2e9e2adf7df241b571228187728191d961dda1f` |
| the `https` 404 page | 146 | `55f7d9e99b8e2d4e0e193b2f0275501e6d9c1ebd29cadbea6a0da48a8587e3e0` |

## Why a networked build does not notice

`ModelGetter.groovy` downloads with `url.openConnection()` and copies
`getInputStream()` straight to the destination file, without looking at the
status. Java's `HttpURLConnection` does not follow a redirect that changes
protocol, so the `http` → `https` 301 is not followed: the stream it hands back
is the 167-byte 301 page, no exception is raised, and the build writes that page
to `ner-person.bin` and to the six others. The build then succeeds.

Verified with a network on 2026-11-04: `vul4j compile` returns success and all
nine `.bin` files in the models directory are 167 bytes.

With no network there is no DNS, the same download raises
`java.net.UnknownHostException: opennlp.sourceforge.net`, nothing catches it,
and the build fails:

```
[ERROR] Failed to execute goal org.codehaus.gmaven:groovy-maven-plugin:2.0:execute
(testSetup) on project tika-parsers: Execution testSetup ... failed:
java.net.UnknownHostException: opennlp.sourceforge.net
```

So network isolation did not break this entry. It made an existing breakage
visible. The entry's figures in the networked baseline of 2026-10-28 (status
`ok`, 983 judged tests) come from a build whose nine NER models were HTML error
pages, and should not be used.

## The attempt to cache them

Caching the files into the grading image was tried on 2026-11-04, the same way
the Maven and Gradle dependency caches are built: a throwaway container started
from `cweft/vul4j-grader`, with a network, downloading into
`/opt/cweft/models/tika` for `make_offline` to seed into each checkout.
`vul4j-alldeps` was not touched.

Every URL was checked before anything was downloaded, with a ranged GET rather
than a HEAD, because a mirror that serves a file will sometimes answer HEAD with
404. Seven of the nine answered 404 with a 146-byte `text/html` body; the two
GitHub-hosted files answered 206 with `application/octet-stream`. Nothing was
downloaded and the image was left unchanged, so there is no file list, size or
digest to record here beyond the two error-page hashes above.

Caching only the two reachable files would not help. The profile activates on
`ner-person.bin` alone, and that is one of the seven that are gone, so the
download still runs and still fails on the first dead URL.

## What would bring it back

Place real copies of the nine files at their paths in the checkout before the
build, from a source that can be cited and hashed, and re-run:

```bash
python vul4j_baseline.py --only VUL4J-36 --redo
```

Caching the files in the grading image and copying them into each checkout is
the same approach already used for the Maven and Gradle dependency caches. It
was not done here because the upstream files are gone: there is nothing to
cache that is known to be what the build originally used.
