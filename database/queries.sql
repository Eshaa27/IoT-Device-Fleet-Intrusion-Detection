-- Count total login attempts
SELECT COUNT(*) FROM auth;

-- Count unique attacker IPs
SELECT COUNT(DISTINCT ip) FROM sessions;

-- Top 10 most tried usernames
SELECT username, COUNT(*) as attempts
FROM auth
GROUP BY username
ORDER BY attempts DESC
LIMIT 10;

-- Top 10 most tried passwords
SELECT password, COUNT(*) as attempts
FROM auth
GROUP BY password
ORDER BY attempts DESC
LIMIT 10;

-- Attack attempts per day
SELECT DATE(timestamp) as date, COUNT(*) as attacks
FROM auth
GROUP BY DATE(timestamp)
ORDER BY date;

-- Sessions by country
SELECT country, COUNT(*) as sessions
FROM sessions_enriched
GROUP BY country
ORDER BY sessions DESC;

-- High threat IPs
SELECT ip, country, abuse_confidence_score, threat_level
FROM enriched_ips
WHERE abuse_confidence_score >= 80
ORDER BY abuse_confidence_score DESC;

-- ML flagged attack sessions
SELECT COUNT(*) as attack_sessions
FROM sessions_enriched
WHERE iso_label = 'attack';

-- MITRE technique frequency
SELECT
    unnest(string_to_array(mitre_techniques, ', ')) as technique,
    COUNT(*) as sessions
FROM sessions_enriched
GROUP BY technique
ORDER BY sessions DESC;