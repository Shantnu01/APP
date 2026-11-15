"""
Unit tests for RepoGuard dependency manifest parsers.
"""

import unittest
from parsers.python_parser import PythonParser
from parsers.npm_parser import NpmParser
from parsers.maven_parser import MavenParser
from parsers.go_parser import GoParser


class TestParsers(unittest.TestCase):
    def test_python_parser(self):
        sample_req = b"""
        # Core requirements
        requests==2.28.1
        urllib3>=1.26.5; python_version > '3.7'
        flask[async]==2.0.1
        --extra-index-url https://pypi.org/simple
        invalid-line-here
        """
        parser = PythonParser()
        deps = parser.parse(sample_req, "requirements.txt")
        names = {d.name for d in deps}
        self.assertIn("requests", names)
        self.assertIn("flask", names)

    def test_npm_parser(self):
        sample_pkg = b"""
        {
          "name": "demo-app",
          "dependencies": {
            "express": "^4.18.2",
            "lodash": "4.17.21"
          },
          "devDependencies": {
            "mocha": "~10.2.0"
          }
        }
        """
        parser = NpmParser()
        deps = parser.parse(sample_pkg, "package.json")
        names = {d.name: d.version for d in deps}
        self.assertEqual(names.get("lodash"), "4.17.21")
        self.assertEqual(names.get("express"), "4.18.2")
        self.assertEqual(names.get("mocha"), "10.2.0")

    def test_go_parser(self):
        sample_go = b"""
        module example.com/demo

        go 1.21

        require (
            github.com/gin-gonic/gin v1.9.1
            golang.org/x/crypto v0.14.0 // indirect
        )
        """
        parser = GoParser()
        deps = parser.parse(sample_go, "go.mod")
        self.assertEqual(len(deps), 2)
        self.assertEqual(deps[0].name, "github.com/gin-gonic/gin")
        self.assertEqual(deps[0].version, "1.9.1")

    def test_maven_fallback(self):
        sample_pom = b"""
        <project>
            <properties>
                <log4j.ver>2.14.1</log4j.ver>
            </properties>
            <dependencies>
                <dependency>
                    <groupId>org.apache.logging.log4j</groupId>
                    <artifactId>log4j-core</artifactId>
                    <version>${log4j.ver}</version>
                </dependency>
            </dependencies>
        </project>
        """
        parser = MavenParser()
        deps = parser._parse_with_python_fallback(sample_pom, "pom.xml")
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].name, "org.apache.logging.log4j:log4j-core")
        self.assertEqual(deps[0].version, "2.14.1")


if __name__ == "__main__":
    unittest.main()
