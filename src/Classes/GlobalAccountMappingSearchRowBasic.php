<?php

class GlobalAccountMappingSearchRowBasic extends SearchRowBasic {
	public $accountingBook;
	public $class;
	public $customDimension;
	public $department;
	public $destinationAccount;
	public $effectiveDate;
	public $endDate;
	public $externalId;
	public $internalId;
	public $location;
	public $sourceAccount;
	public $subsidiary;
	public $customFieldList;
	static $paramtypesmap = array(
		"accountingBook" => "SearchColumnSelectField[]",
		"class" => "SearchColumnSelectField[]",
		"customDimension" => "SearchColumnSelectCustomField[]",
		"department" => "SearchColumnSelectField[]",
		"destinationAccount" => "SearchColumnSelectField[]",
		"effectiveDate" => "SearchColumnDateField[]",
		"endDate" => "SearchColumnDateField[]",
		"externalId" => "SearchColumnStringField[]",
		"internalId" => "SearchColumnSelectField[]",
		"location" => "SearchColumnSelectField[]",
		"sourceAccount" => "SearchColumnSelectField[]",
		"subsidiary" => "SearchColumnSelectField[]",
		"customFieldList" => "SearchColumnCustomFieldList",
	);
}
