<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;

class Aite extends ParserBase
{

    /**
     * Parse attachments
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        try {
            $regex = config("{$this->configBase}.parser.file_regex");
            preg_match($regex, '', $matches);
        } catch (\Exception $e) {
            $this->warningCount++;
            return $this->failed('Configuration error in the regular expression');
        }
        $attachments = $this->parsedMail->getAttachments();
        foreach ($attachments as $attachment) {
            $this->parseAttachment($attachment);
        }
        return $this->success();
    }
    
    /**
     * Parse attachment
     * @param $attachment @see $this->parsedMail->getAttachments();
     * @return void
     */
    private function parseAttachment($attachment)
    {
        $isAttachedFileCsvInZip = strpos($attachment->filename, '.gz') !== false
            && $attachment->contentType == 'application/octet-stream';
        if (!$isAttachedFileCsvInZip) {
            $this->warningCount++;
            return;
        }

        $report = json_decode(gzdecode($attachment->getContent()), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            // Pregmatch failed to get feedName from attachment
            $this->warningCount++;
            return;
        }
        $this->feedName = 'THREAT_ALERT';

        $kae = $this->isKnownFeed() && $this->isEnabledFeed();
        if (!$kae) {
            return;
        }
        // If feed is known and enabled, validate data and save report

        // Handle field mappings first
        $aliases = config("{$this->configBase}.feeds.{$this->feedName}.aliasses");
        $aliases = is_array($aliases) ? $aliases : [];
        foreach ($aliases as $alias => $real) {
            if (!isset($report[$alias]) {
                continue;
            }
            $report[$real] = $report[$alias];
            unset($report[$alias]);
        }

        // Sanity check
        if ($this->hasRequiredFields($report) !== true) {
            return;
        }
        // incident has all requirements met, filter and add!
        $report = $this->applyFilters($report);

        $incident = new Incident();
        $incident->source      = $report['owner']['name'];
        $incident->source_id   = $report['id'];
        $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
        $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
        $incident->timestamp   = strtotime($report['last_updated']);
        $incident->information = json_encode([]);

        switch($report['type']) {
            case 'URI':
                $incident->ip          = $report['enrichments']['domain_address'];
                $incident->domain      = $report['enrichments']['domain_name'];
                break;
            case 'IP_ADDRESS':
                $incident->ip          = $report['raw_indicator'];
                break;
        }

        //unset($report['enrichments']);
        unset($report['owner']);
        $incident->information = json_encode($report);

        $this->incidents[] = $incident;
    }
}
