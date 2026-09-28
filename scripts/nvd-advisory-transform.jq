# Canonical NVD CVE -> ClawSec advisory transform.
#
# Publication is deliberately strict: product identity and version scope must
# come from the same allowlisted vulnerable application CPE match. References
# and free text are discovery signals only.

def map_severity:
  if . == null then "medium"
  elif . >= 9.0 then "critical"
  elif . >= 7.0 then "high"
  elif . >= 4.0 then "medium"
  else "low"
  end;

def get_cvss_score:
  .cve.metrics.cvssMetricV40[0]?.cvssData.baseScore //
  .cve.metrics.cvssMetricV31[0]?.cvssData.baseScore //
  .cve.metrics.cvssMetricV30[0]?.cvssData.baseScore //
  .cve.metrics.cvssMetricV2[0]?.cvssData.baseScore //
  null;

def nvd_category_raw:
  (
    [.cve.weaknesses[]?.description[]? | select(.lang == "en") | .value | strings | select(length > 0)]
    | unique
    | map(select(. != "NVD-CWE-noinfo" and . != "NVD-CWE-Other"))
    | .[0]
  );

def cwe_id:
  (
    nvd_category_raw
    | if . == null then null
      else (try (capture("^CWE-(?<id>[0-9]+)$").id) catch null)
      end
  );

def cwe_name_map($id):
  ({
    "20": "improper_input_validation",
    "22": "path_traversal",
    "77": "command_injection",
    "78": "os_command_injection",
    "79": "cross_site_scripting",
    "89": "sql_injection",
    "94": "code_injection",
    "119": "memory_buffer_bounds_violation",
    "120": "classic_buffer_overflow",
    "125": "out_of_bounds_read",
    "134": "format_string_vulnerability",
    "200": "exposure_of_sensitive_information",
    "250": "execution_with_unnecessary_privileges",
    "269": "improper_privilege_management",
    "284": "improper_access_control",
    "285": "improper_authorization",
    "287": "improper_authentication",
    "295": "improper_certificate_validation",
    "306": "missing_authentication_for_critical_function",
    "319": "cleartext_transmission_of_sensitive_information",
    "326": "inadequate_encryption_strength",
    "327": "risky_cryptographic_algorithm",
    "352": "cross_site_request_forgery",
    "362": "race_condition",
    "400": "uncontrolled_resource_consumption",
    "416": "use_after_free",
    "434": "unrestricted_file_upload",
    "502": "deserialization_of_untrusted_data",
    "601": "open_redirect",
    "611": "xml_external_entity_injection",
    "639": "insecure_direct_object_reference",
    "668": "exposure_of_resource_to_wrong_sphere",
    "669": "incorrect_resource_transfer_between_spheres",
    "732": "incorrect_permission_assignment",
    "787": "out_of_bounds_write",
    "798": "hard_coded_credentials",
    "862": "missing_authorization",
    "863": "incorrect_authorization",
    "918": "server_side_request_forgery",
    "922": "insecure_storage_of_sensitive_information"
  }[$id]);

def nvd_category_name:
  (
    cwe_id as $id
    | if $id == null then "unspecified_weakness"
      else (cwe_name_map($id) // ("unknown_cwe_" + $id))
      end
  );

def cpe_unescape:
  gsub("\\\\"; "");

def cpe_fields($criteria):
  ($criteria | split(":")) as $parts
  | if ($parts | length) < 6
      or ($parts[0] | ascii_downcase) != "cpe"
      or $parts[1] != "2.3"
    then null
    else {
      part: ($parts[2] | ascii_downcase),
      vendor: ($parts[3] | cpe_unescape | ascii_downcase),
      product: ($parts[4] | cpe_unescape | ascii_downcase),
      version: ($parts[5] | cpe_unescape),
      update: (($parts[6] // "*") | cpe_unescape)
    }
    end;

def supported_component_for_cpe($criteria):
  cpe_fields($criteria) as $cpe
  | if $cpe == null or $cpe.part != "a" then null
    elif $cpe.vendor == "openclaw" and $cpe.product == "openclaw" then "openclaw"
    elif (($cpe.vendor == "nanoco" or $cpe.vendor == "qwibitai") and $cpe.product == "nanoclaw") then "nanoclaw"
    elif $cpe.vendor == "software-metadata.pub" and $cpe.product == "hermes" then "hermes"
    elif $cpe.vendor == "nousresearch" and $cpe.product == "hermes_agent" then "hermes"
    elif (($cpe.vendor == "sipeed" or $cpe.vendor == "picoclaw") and $cpe.product == "picoclaw") then "picoclaw"
    elif $cpe.vendor == "nvidia" and $cpe.product == "nemoclaw" then "nemoclaw"
    elif $cpe.vendor == "nvidia" and $cpe.product == "openshell" then "openshell"
    else null
    end;

def vulnerable_application_cpe_matches:
  [
    .cve.configurations[]?
    | ..
    | objects
    | select(.vulnerable == true)
    | select((.criteria? | type) == "string")
    | select((cpe_fields(.criteria).part // null) == "a")
  ];

def scoped_cpe_matches:
  [
    vulnerable_application_cpe_matches[]
    | supported_component_for_cpe(.criteria) as $component
    | select($component != null)
    | . + {component: $component}
  ];

def cpe_exact_version($criteria):
  cpe_fields($criteria) as $cpe
  | if $cpe == null or $cpe.version == "" or $cpe.version == "*" or $cpe.version == "-" then null
    elif $cpe.update == "" or $cpe.update == "*" or $cpe.update == "-" then $cpe.version
    else ($cpe.version + "-" + $cpe.update)
    end;

def explicit_version_scope:
  (
    [
      (if ((.versionStartIncluding? | type) == "string") and (.versionStartIncluding | length > 0)
       then ">=" + .versionStartIncluding else empty end),
      (if ((.versionStartExcluding? | type) == "string") and (.versionStartExcluding | length > 0)
       then ">" + .versionStartExcluding else empty end),
      (if ((.versionEndIncluding? | type) == "string") and (.versionEndIncluding | length > 0)
       then "<=" + .versionEndIncluding else empty end),
      (if ((.versionEndExcluding? | type) == "string") and (.versionEndExcluding | length > 0)
       then "<" + .versionEndExcluding else empty end)
    ]
    | join(" ")
  ) as $range
  | if ($range | length) > 0 then $range
    else cpe_exact_version(.criteria)
    end;

def supported_scoped_targets:
  (
    scoped_cpe_matches
    | map(
      explicit_version_scope as $scope
      | select($scope != null and ($scope | length) > 0)
      | {
          component,
          selector: (.component + "@" + $scope)
        }
    )
    | unique_by(.selector)
    | sort_by(.component, .selector)
  );

def has_supported_scoped_target:
  (supported_scoped_targets | length) > 0;

def preferred_description:
  (
    (.cve.descriptions[]? | select(.lang == "en") | .value)
    // .cve.descriptions[0]?.value
    // "No description provided by NVD."
  );

def nvd_advisory:
  supported_scoped_targets as $targets
  | select(($targets | length) > 0)
  | {
      id: .cve.id,
      severity: (get_cvss_score | map_severity),
      type: nvd_category_name,
      nvd_category_id: nvd_category_raw,
      title: (preferred_description | .[0:100] + (if length > 100 then "..." else "" end)),
      description: preferred_description,
      affected: ($targets | map(.selector)),
      platforms: ($targets | map(.component) | unique),
      action: "Review and update affected components. See NVD for remediation details.",
      published: .cve.published,
      references: ([.cve.references[]?.url // empty] | unique),
      cvss_score: get_cvss_score,
      nvd_url: ("https://nvd.nist.gov/vuln/detail/" + .cve.id),
      exploitability_score: null,
      exploitability_rationale: null
    };

def nvd_advisory_current_state:
  nvd_advisory
  | {
      id,
      severity,
      type,
      nvd_category_id,
      cvss_score,
      description,
      title,
      affected,
      platforms,
      references,
      exploitability_score,
      exploitability_rationale
    };
