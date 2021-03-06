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

class BinWorksheetItem {
    public $item;
    public $itemName;
    public $description;
    public $quantity;
    public $itemOnHand;
    public $itemUnitsLabel;
    public $inventoryDetail;
    public $itemBins;
    public $itemBinNumbers;
    public $itemBinList;
    public $itemPreferBin;
    public $itemBlank;
    static $paramtypesmap = array(
        "item" => "RecordRef",
        "itemName" => "string",
        "description" => "string",
        "quantity" => "float",
        "itemOnHand" => "string",
        "itemUnitsLabel" => "string",
        "inventoryDetail" => "InventoryDetail",
        "itemBins" => "string",
        "itemBinNumbers" => "string",
        "itemBinList" => "string",
        "itemPreferBin" => "string",
        "itemBlank" => "string",
    );
}
