# An unsupported source-address family has no valid classification.
if ($reference_exit_membership = unavailable) { return 503; }
if ($reference_exit_membership = listed) { return 403; }
