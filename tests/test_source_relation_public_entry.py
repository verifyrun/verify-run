import io
import unittest
from unittest.mock import patch
from vfy import cli, service_source_relation_cli

class PublicSourceRelationEntry(unittest.TestCase):
    def test_exact_public_name_routes_to_existing_reader(self):
        output=io.StringIO()
        with patch.object(service_source_relation_cli,'run',return_value=12) as selected:
            self.assertEqual(cli.main(['inspect-service-source-relation','--request-sha256','a'*64],out=output,err=io.StringIO()),12)
        self.assertEqual(selected.call_count,1)
        self.assertEqual(selected.call_args.kwargs['request_sha256'],'a'*64)
        self.assertIs(selected.call_args.kwargs['out'],output)
