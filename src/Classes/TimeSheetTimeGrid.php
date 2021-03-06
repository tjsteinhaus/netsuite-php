<?php
/**
 * This file is part of the SevenShores/NetSuite library
 * AND originally from the NetSuite PHP Toolkit.
 *
 * New content:
 * @package    ryanwinchester/netsuite-php
 * @copyright  Copyright (c) Ryan Winchester
 * @license    http://www.apache.org/licenses/LICENSE-2.0 Apache-2.0
 * @link       https://github.com/ryanwinchester/netsuite-php
 *
 * Original content:
 * @copyright  Copyright (c) NetSuite Inc.
 * @license    https://raw.githubusercontent.com/ryanwinchester/netsuite-php/master/original/NetSuite%20Application%20Developer%20License%20Agreement.txt
 * @link       http://www.netsuite.com/portal/developers/resources/suitetalk-sample-applications.shtml
 *
 * generated:  2017-08-22 02:41:36 PM CDT
 */

namespace NetSuite\Classes;

class TimeSheetTimeGrid {
    public $sunday;
    public $monday;
    public $tuesday;
    public $wednesday;
    public $thursday;
    public $friday;
    public $saturday;
    static $paramtypesmap = array(
        "sunday" => "TimeEntry",
        "monday" => "TimeEntry",
        "tuesday" => "TimeEntry",
        "wednesday" => "TimeEntry",
        "thursday" => "TimeEntry",
        "friday" => "TimeEntry",
        "saturday" => "TimeEntry",
    );
}
