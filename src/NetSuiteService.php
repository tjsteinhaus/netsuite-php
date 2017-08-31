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
 * created:    2015-01-22  1:04 PM
 * updated:    2017-08-22 02:41:36 PM CDT
 */

namespace NetSuite;

use NetSuite\Classes;

class NetSuiteService extends NetSuiteClient {

	public $generated_from_endpoint = "2017_1";
	/**
	 * Class map for wsdl=>php
	 * @var array
	 */
	protected $classmap = array(
		"RecordType" => "NetSuite\Classes\RecordType",
		"SearchRecordType" => "NetSuite\Classes\SearchRecordType",
		"GetAllRecordType" => "NetSuite\Classes\GetAllRecordType",
		"GetCustomizationType" => "NetSuite\Classes\GetCustomizationType",
		"InitializeType" => "NetSuite\Classes\InitializeType",
		"InitializeRefType" => "NetSuite\Classes\InitializeRefType",
		"InitializeAuxRefType" => "NetSuite\Classes\InitializeAuxRefType",
		"DeletedRecordType" => "NetSuite\Classes\DeletedRecordType",
		"AsyncStatusType" => "NetSuite\Classes\AsyncStatusType",
		"SearchStringFieldOperator" => "NetSuite\Classes\SearchStringFieldOperator",
		"SearchLongFieldOperator" => "NetSuite\Classes\SearchLongFieldOperator",
		"SearchTextNumberFieldOperator" => "NetSuite\Classes\SearchTextNumberFieldOperator",
		"SearchDoubleFieldOperator" => "NetSuite\Classes\SearchDoubleFieldOperator",
		"SearchDateFieldOperator" => "NetSuite\Classes\SearchDateFieldOperator",
		"SearchEnumMultiSelectFieldOperator" => "NetSuite\Classes\SearchEnumMultiSelectFieldOperator",
		"SearchMultiSelectFieldOperator" => "NetSuite\Classes\SearchMultiSelectFieldOperator",
		"SearchDate" => "NetSuite\Classes\SearchDate",
		"DurationUnit" => "NetSuite\Classes\DurationUnit",
		"CalendarEventAttendeeResponse" => "NetSuite\Classes\CalendarEventAttendeeResponse",
		"GetSelectValueFilterOperator" => "NetSuite\Classes\GetSelectValueFilterOperator",
		"SignatureAlgorithm" => "NetSuite\Classes\SignatureAlgorithm",
		"StatusDetailType" => "NetSuite\Classes\StatusDetailType",
		"StatusDetailCodeType" => "NetSuite\Classes\StatusDetailCodeType",
		"FaultCodeType" => "NetSuite\Classes\FaultCodeType",
		"Passport" => "NetSuite\Classes\Passport",
		"SsoPassport" => "NetSuite\Classes\SsoPassport",
		"SsoCredentials" => "NetSuite\Classes\SsoCredentials",
		"TokenPassportSignature" => "NetSuite\Classes\TokenPassportSignature",
		"TokenPassport" => "NetSuite\Classes\TokenPassport",
		"ChangePassword" => "NetSuite\Classes\ChangePassword",
		"ChangeEmail" => "NetSuite\Classes\ChangeEmail",
		"StatusDetail" => "NetSuite\Classes\StatusDetail",
		"Status" => "NetSuite\Classes\Status",
		"WsRole" => "NetSuite\Classes\WsRole",
		"WsRoleList" => "NetSuite\Classes\WsRoleList",
		"Record" => "NetSuite\Classes\Record",
		"NullField" => "NetSuite\Classes\NullField",
		"SearchRecord" => "NetSuite\Classes\SearchRecord",
		"SearchRecordBasic" => "NetSuite\Classes\SearchRecordBasic",
		"SearchRow" => "NetSuite\Classes\SearchRow",
		"SearchRowBasic" => "NetSuite\Classes\SearchRowBasic",
		"SearchResult" => "NetSuite\Classes\SearchResult",
		"AsyncStatusResult" => "NetSuite\Classes\AsyncStatusResult",
		"GetAllResult" => "NetSuite\Classes\GetAllResult",
		"GetSavedSearchResult" => "NetSuite\Classes\GetSavedSearchResult",
		"GetCustomizationIdResult" => "NetSuite\Classes\GetCustomizationIdResult",
		"GetSelectValueResult" => "NetSuite\Classes\GetSelectValueResult",
		"RecordList" => "NetSuite\Classes\RecordList",
		"SearchRowList" => "NetSuite\Classes\SearchRowList",
		"RecordRefList" => "NetSuite\Classes\RecordRefList",
		"BaseRef" => "NetSuite\Classes\BaseRef",
		"BaseRefList" => "NetSuite\Classes\BaseRefList",
		"RecordRef" => "NetSuite\Classes\RecordRef",
		"Duration" => "NetSuite\Classes\Duration",
		"CustomRecordRef" => "NetSuite\Classes\CustomRecordRef",
		"CustomTransactionRef" => "NetSuite\Classes\CustomTransactionRef",
		"CustomizationRef" => "NetSuite\Classes\CustomizationRef",
		"CustomizationRefList" => "NetSuite\Classes\CustomizationRefList",
		"InitializeRecord" => "NetSuite\Classes\InitializeRecord",
		"InitializeRef" => "NetSuite\Classes\InitializeRef",
		"InitializeRefList" => "NetSuite\Classes\InitializeRefList",
		"InitializeAuxRef" => "NetSuite\Classes\InitializeAuxRef",
		"UpdateInviteeStatusReference" => "NetSuite\Classes\UpdateInviteeStatusReference",
		"GetAllRecord" => "NetSuite\Classes\GetAllRecord",
		"GetSavedSearchRecord" => "NetSuite\Classes\GetSavedSearchRecord",
		"CustomizationType" => "NetSuite\Classes\CustomizationType",
		"ListOrRecordRef" => "NetSuite\Classes\ListOrRecordRef",
		"CustomFieldRef" => "NetSuite\Classes\CustomFieldRef",
		"LongCustomFieldRef" => "NetSuite\Classes\LongCustomFieldRef",
		"DoubleCustomFieldRef" => "NetSuite\Classes\DoubleCustomFieldRef",
		"BooleanCustomFieldRef" => "NetSuite\Classes\BooleanCustomFieldRef",
		"StringCustomFieldRef" => "NetSuite\Classes\StringCustomFieldRef",
		"DateCustomFieldRef" => "NetSuite\Classes\DateCustomFieldRef",
		"SelectCustomFieldRef" => "NetSuite\Classes\SelectCustomFieldRef",
		"MultiSelectCustomFieldRef" => "NetSuite\Classes\MultiSelectCustomFieldRef",
		"CustomFieldList" => "NetSuite\Classes\CustomFieldList",
		"DimensionRef" => "NetSuite\Classes\DimensionRef",
		"StringDimensionRef" => "NetSuite\Classes\StringDimensionRef",
		"SelectDimensionRef" => "NetSuite\Classes\SelectDimensionRef",
		"DimensionList" => "NetSuite\Classes\DimensionList",
		"SearchBooleanField" => "NetSuite\Classes\SearchBooleanField",
		"SearchStringField" => "NetSuite\Classes\SearchStringField",
		"SearchLongField" => "NetSuite\Classes\SearchLongField",
		"SearchTextNumberField" => "NetSuite\Classes\SearchTextNumberField",
		"SearchDoubleField" => "NetSuite\Classes\SearchDoubleField",
		"SearchDateField" => "NetSuite\Classes\SearchDateField",
		"SearchEnumMultiSelectField" => "NetSuite\Classes\SearchEnumMultiSelectField",
		"SearchMultiSelectField" => "NetSuite\Classes\SearchMultiSelectField",
		"SearchCustomField" => "NetSuite\Classes\SearchCustomField",
		"SearchBooleanCustomField" => "NetSuite\Classes\SearchBooleanCustomField",
		"SearchStringCustomField" => "NetSuite\Classes\SearchStringCustomField",
		"SearchLongCustomField" => "NetSuite\Classes\SearchLongCustomField",
		"SearchDoubleCustomField" => "NetSuite\Classes\SearchDoubleCustomField",
		"SearchDateCustomField" => "NetSuite\Classes\SearchDateCustomField",
		"SearchEnumMultiSelectCustomField" => "NetSuite\Classes\SearchEnumMultiSelectCustomField",
		"SearchMultiSelectCustomField" => "NetSuite\Classes\SearchMultiSelectCustomField",
		"SearchCustomFieldList" => "NetSuite\Classes\SearchCustomFieldList",
		"SearchColumnField" => "NetSuite\Classes\SearchColumnField",
		"SearchColumnBooleanField" => "NetSuite\Classes\SearchColumnBooleanField",
		"SearchColumnStringField" => "NetSuite\Classes\SearchColumnStringField",
		"SearchColumnLongField" => "NetSuite\Classes\SearchColumnLongField",
		"SearchColumnTextNumberField" => "NetSuite\Classes\SearchColumnTextNumberField",
		"SearchColumnDoubleField" => "NetSuite\Classes\SearchColumnDoubleField",
		"SearchColumnDateField" => "NetSuite\Classes\SearchColumnDateField",
		"SearchColumnEnumSelectField" => "NetSuite\Classes\SearchColumnEnumSelectField",
		"SearchColumnSelectField" => "NetSuite\Classes\SearchColumnSelectField",
		"SearchColumnCustomField" => "NetSuite\Classes\SearchColumnCustomField",
		"SearchColumnBooleanCustomField" => "NetSuite\Classes\SearchColumnBooleanCustomField",
		"SearchColumnStringCustomField" => "NetSuite\Classes\SearchColumnStringCustomField",
		"SearchColumnLongCustomField" => "NetSuite\Classes\SearchColumnLongCustomField",
		"SearchColumnDoubleCustomField" => "NetSuite\Classes\SearchColumnDoubleCustomField",
		"SearchColumnDateCustomField" => "NetSuite\Classes\SearchColumnDateCustomField",
		"SearchColumnEnumMultiSelectCustomField" => "NetSuite\Classes\SearchColumnEnumMultiSelectCustomField",
		"SearchColumnSelectCustomField" => "NetSuite\Classes\SearchColumnSelectCustomField",
		"SearchColumnMultiSelectCustomField" => "NetSuite\Classes\SearchColumnMultiSelectCustomField",
		"SearchColumnCustomFieldList" => "NetSuite\Classes\SearchColumnCustomFieldList",
		"ItemAvailabilityFilter" => "NetSuite\Classes\ItemAvailabilityFilter",
		"ItemAvailability" => "NetSuite\Classes\ItemAvailability",
		"ItemAvailabilityList" => "NetSuite\Classes\ItemAvailabilityList",
		"GetItemAvailabilityResult" => "NetSuite\Classes\GetItemAvailabilityResult",
		"BudgetExchangeRateFilter" => "NetSuite\Classes\BudgetExchangeRateFilter",
		"BudgetExchangeRate" => "NetSuite\Classes\BudgetExchangeRate",
		"BudgetExchangeRateList" => "NetSuite\Classes\BudgetExchangeRateList",
		"GetBudgetExchangeRateResult" => "NetSuite\Classes\GetBudgetExchangeRateResult",
		"CurrencyRateFilter" => "NetSuite\Classes\CurrencyRateFilter",
		"CurrencyRate" => "NetSuite\Classes\CurrencyRate",
		"CurrencyRateList" => "NetSuite\Classes\CurrencyRateList",
		"GetCurrencyRateResult" => "NetSuite\Classes\GetCurrencyRateResult",
		"DataCenterUrls" => "NetSuite\Classes\DataCenterUrls",
		"GetDataCenterUrlsResult" => "NetSuite\Classes\GetDataCenterUrlsResult",
		"PostingTransactionSummaryField" => "NetSuite\Classes\PostingTransactionSummaryField",
		"PostingTransactionSummaryFilter" => "NetSuite\Classes\PostingTransactionSummaryFilter",
		"PostingTransactionSummary" => "NetSuite\Classes\PostingTransactionSummary",
		"PostingTransactionSummaryList" => "NetSuite\Classes\PostingTransactionSummaryList",
		"GetPostingTransactionSummaryResult" => "NetSuite\Classes\GetPostingTransactionSummaryResult",
		"GetSelectValueFieldDescription" => "NetSuite\Classes\GetSelectValueFieldDescription",
		"GetSelectValueFilter" => "NetSuite\Classes\GetSelectValueFilter",
		"GetSelectFilterByFieldValueList" => "NetSuite\Classes\GetSelectFilterByFieldValueList",
		"GetSelectFilterByFieldValue" => "NetSuite\Classes\GetSelectFilterByFieldValue",
		"GetServerTimeResult" => "NetSuite\Classes\GetServerTimeResult",
		"DeletedRecord" => "NetSuite\Classes\DeletedRecord",
		"DeletedRecordList" => "NetSuite\Classes\DeletedRecordList",
		"GetDeletedResult" => "NetSuite\Classes\GetDeletedResult",
		"GetDeletedFilter" => "NetSuite\Classes\GetDeletedFilter",
		"AttachReference" => "NetSuite\Classes\AttachReference",
		"DetachReference" => "NetSuite\Classes\DetachReference",
		"AttachContactReference" => "NetSuite\Classes\AttachContactReference",
		"AttachBasicReference" => "NetSuite\Classes\AttachBasicReference",
		"DetachBasicReference" => "NetSuite\Classes\DetachBasicReference",
		"DeletionReason" => "NetSuite\Classes\DeletionReason",
		"SoapFault" => "NetSuite\Classes\NSSoapFault",
		"InsufficientPermissionFault" => "NetSuite\Classes\InsufficientPermissionFault",
		"InvalidAccountFault" => "NetSuite\Classes\InvalidAccountFault",
		"InvalidCredentialsFault" => "NetSuite\Classes\InvalidCredentialsFault",
		"InvalidSessionFault" => "NetSuite\Classes\InvalidSessionFault",
		"ExceededConcurrentRequestLimitFault" => "NetSuite\Classes\ExceededConcurrentRequestLimitFault",
		"ExceededRequestLimitFault" => "NetSuite\Classes\ExceededRequestLimitFault",
		"ExceededUsageLimitFault" => "NetSuite\Classes\ExceededUsageLimitFault",
		"ExceededRecordCountFault" => "NetSuite\Classes\ExceededRecordCountFault",
		"InvalidVersionFault" => "NetSuite\Classes\InvalidVersionFault",
		"ExceededRequestSizeFault" => "NetSuite\Classes\ExceededRequestSizeFault",
		"AsyncFault" => "NetSuite\Classes\AsyncFault",
		"UnexpectedErrorFault" => "NetSuite\Classes\UnexpectedErrorFault",
		"ApplicationInfo" => "NetSuite\Classes\ApplicationInfo",
		"PartnerInfo" => "NetSuite\Classes\PartnerInfo",
		"DocumentInfo" => "NetSuite\Classes\DocumentInfo",
		"Preferences" => "NetSuite\Classes\Preferences",
		"SearchPreferences" => "NetSuite\Classes\SearchPreferences",
		"SessionResponse" => "NetSuite\Classes\SessionResponse",
		"WriteResponse" => "NetSuite\Classes\WriteResponse",
		"ReadResponse" => "NetSuite\Classes\ReadResponse",
		"WriteResponseList" => "NetSuite\Classes\WriteResponseList",
		"ReadResponseList" => "NetSuite\Classes\ReadResponseList",
		"LoginResponse" => "NetSuite\Classes\LoginResponse",
		"SsoLoginResponse" => "NetSuite\Classes\SsoLoginResponse",
		"MapSsoResponse" => "NetSuite\Classes\MapSsoResponse",
		"ChangePasswordResponse" => "NetSuite\Classes\ChangePasswordResponse",
		"ChangeEmailResponse" => "NetSuite\Classes\ChangeEmailResponse",
		"LogoutResponse" => "NetSuite\Classes\LogoutResponse",
		"AddResponse" => "NetSuite\Classes\AddResponse",
		"AddListResponse" => "NetSuite\Classes\AddListResponse",
		"UpdateResponse" => "NetSuite\Classes\UpdateResponse",
		"UpdateListResponse" => "NetSuite\Classes\UpdateListResponse",
		"UpsertResponse" => "NetSuite\Classes\UpsertResponse",
		"UpsertListResponse" => "NetSuite\Classes\UpsertListResponse",
		"DeleteResponse" => "NetSuite\Classes\DeleteResponse",
		"DeleteListResponse" => "NetSuite\Classes\DeleteListResponse",
		"SearchResponse" => "NetSuite\Classes\SearchResponse",
		"SearchMoreResponse" => "NetSuite\Classes\SearchMoreResponse",
		"SearchMoreWithIdResponse" => "NetSuite\Classes\SearchMoreWithIdResponse",
		"SearchNextResponse" => "NetSuite\Classes\SearchNextResponse",
		"GetResponse" => "NetSuite\Classes\GetResponse",
		"GetListResponse" => "NetSuite\Classes\GetListResponse",
		"GetAllResponse" => "NetSuite\Classes\GetAllResponse",
		"GetSavedSearchResponse" => "NetSuite\Classes\GetSavedSearchResponse",
		"GetCustomizationIdResponse" => "NetSuite\Classes\GetCustomizationIdResponse",
		"InitializeResponse" => "NetSuite\Classes\InitializeResponse",
		"InitializeListResponse" => "NetSuite\Classes\InitializeListResponse",
		"getSelectValueResponse" => "NetSuite\Classes\getSelectValueResponse",
		"GetItemAvailabilityResponse" => "NetSuite\Classes\GetItemAvailabilityResponse",
		"GetBudgetExchangeRateResponse" => "NetSuite\Classes\GetBudgetExchangeRateResponse",
		"GetCurrencyRateResponse" => "NetSuite\Classes\GetCurrencyRateResponse",
		"GetDataCenterUrlsResponse" => "NetSuite\Classes\GetDataCenterUrlsResponse",
		"GetPostingTransactionSummaryResponse" => "NetSuite\Classes\GetPostingTransactionSummaryResponse",
		"GetServerTimeResponse" => "NetSuite\Classes\GetServerTimeResponse",
		"AttachResponse" => "NetSuite\Classes\AttachResponse",
		"DetachResponse" => "NetSuite\Classes\DetachResponse",
		"UpdateInviteeStatusResponse" => "NetSuite\Classes\UpdateInviteeStatusResponse",
		"UpdateInviteeStatusListResponse" => "NetSuite\Classes\UpdateInviteeStatusListResponse",
		"AsyncStatusResponse" => "NetSuite\Classes\AsyncStatusResponse",
		"GetAsyncResultResponse" => "NetSuite\Classes\GetAsyncResultResponse",
		"AsyncResult" => "NetSuite\Classes\AsyncResult",
		"AsyncAddListResult" => "NetSuite\Classes\AsyncAddListResult",
		"AsyncUpdateListResult" => "NetSuite\Classes\AsyncUpdateListResult",
		"AsyncUpsertListResult" => "NetSuite\Classes\AsyncUpsertListResult",
		"AsyncDeleteListResult" => "NetSuite\Classes\AsyncDeleteListResult",
		"AsyncGetListResult" => "NetSuite\Classes\AsyncGetListResult",
		"AsyncSearchResult" => "NetSuite\Classes\AsyncSearchResult",
		"AsyncInitializeListResult" => "NetSuite\Classes\AsyncInitializeListResult",
		"GetDeletedResponse" => "NetSuite\Classes\GetDeletedResponse",
		"LoginRequest" => "NetSuite\Classes\LoginRequest",
		"SsoLoginRequest" => "NetSuite\Classes\SsoLoginRequest",
		"MapSsoRequest" => "NetSuite\Classes\MapSsoRequest",
		"ChangePasswordRequest" => "NetSuite\Classes\ChangePasswordRequest",
		"ChangeEmailRequest" => "NetSuite\Classes\ChangeEmailRequest",
		"LogoutRequest" => "NetSuite\Classes\LogoutRequest",
		"AddRequest" => "NetSuite\Classes\AddRequest",
		"DeleteRequest" => "NetSuite\Classes\DeleteRequest",
		"SearchRequest" => "NetSuite\Classes\SearchRequest",
		"SearchMoreRequest" => "NetSuite\Classes\SearchMoreRequest",
		"SearchMoreWithIdRequest" => "NetSuite\Classes\SearchMoreWithIdRequest",
		"SearchNextRequest" => "NetSuite\Classes\SearchNextRequest",
		"UpdateRequest" => "NetSuite\Classes\UpdateRequest",
		"UpsertRequest" => "NetSuite\Classes\UpsertRequest",
		"AddListRequest" => "NetSuite\Classes\AddListRequest",
		"DeleteListRequest" => "NetSuite\Classes\DeleteListRequest",
		"UpdateListRequest" => "NetSuite\Classes\UpdateListRequest",
		"UpsertListRequest" => "NetSuite\Classes\UpsertListRequest",
		"GetRequest" => "NetSuite\Classes\GetRequest",
		"GetListRequest" => "NetSuite\Classes\GetListRequest",
		"GetAllRequest" => "NetSuite\Classes\GetAllRequest",
		"GetSavedSearchRequest" => "NetSuite\Classes\GetSavedSearchRequest",
		"GetCustomizationIdRequest" => "NetSuite\Classes\GetCustomizationIdRequest",
		"InitializeRequest" => "NetSuite\Classes\InitializeRequest",
		"InitializeListRequest" => "NetSuite\Classes\InitializeListRequest",
		"getSelectValueRequest" => "NetSuite\Classes\getSelectValueRequest",
		"GetItemAvailabilityRequest" => "NetSuite\Classes\GetItemAvailabilityRequest",
		"GetBudgetExchangeRateRequest" => "NetSuite\Classes\GetBudgetExchangeRateRequest",
		"GetCurrencyRateRequest" => "NetSuite\Classes\GetCurrencyRateRequest",
		"GetDataCenterUrlsRequest" => "NetSuite\Classes\GetDataCenterUrlsRequest",
		"GetPostingTransactionSummaryRequest" => "NetSuite\Classes\GetPostingTransactionSummaryRequest",
		"GetServerTimeRequest" => "NetSuite\Classes\GetServerTimeRequest",
		"AttachRequest" => "NetSuite\Classes\AttachRequest",
		"DetachRequest" => "NetSuite\Classes\DetachRequest",
		"AsyncAddListRequest" => "NetSuite\Classes\AsyncAddListRequest",
		"UpdateInviteeStatusRequest" => "NetSuite\Classes\UpdateInviteeStatusRequest",
		"UpdateInviteeStatusListRequest" => "NetSuite\Classes\UpdateInviteeStatusListRequest",
		"AsyncUpdateListRequest" => "NetSuite\Classes\AsyncUpdateListRequest",
		"AsyncUpsertListRequest" => "NetSuite\Classes\AsyncUpsertListRequest",
		"AsyncDeleteListRequest" => "NetSuite\Classes\AsyncDeleteListRequest",
		"AsyncGetListRequest" => "NetSuite\Classes\AsyncGetListRequest",
		"AsyncInitializeListRequest" => "NetSuite\Classes\AsyncInitializeListRequest",
		"AsyncSearchRequest" => "NetSuite\Classes\AsyncSearchRequest",
		"CheckAsyncStatusRequest" => "NetSuite\Classes\CheckAsyncStatusRequest",
		"GetAsyncResultRequest" => "NetSuite\Classes\GetAsyncResultRequest",
		"GetDeletedRequest" => "NetSuite\Classes\GetDeletedRequest",
		"Country" => "NetSuite\Classes\Country",
		"Language" => "NetSuite\Classes\Language",
		"AvsMatchCode" => "NetSuite\Classes\AvsMatchCode",
		"CscMatchCode" => "NetSuite\Classes\CscMatchCode",
		"VsoeSopGroup" => "NetSuite\Classes\VsoeSopGroup",
		"VsoeDeferral" => "NetSuite\Classes\VsoeDeferral",
		"VsoePermitDiscount" => "NetSuite\Classes\VsoePermitDiscount",
		"RevenueStatus" => "NetSuite\Classes\RevenueStatus",
		"RevenueCommitStatus" => "NetSuite\Classes\RevenueCommitStatus",
		"PostingPeriodDate" => "NetSuite\Classes\PostingPeriodDate",
		"PermissionLevel" => "NetSuite\Classes\PermissionLevel",
		"Source" => "NetSuite\Classes\Source",
		"GlobalSubscriptionStatus" => "NetSuite\Classes\GlobalSubscriptionStatus",
		"ItemCostEstimateType" => "NetSuite\Classes\ItemCostEstimateType",
		"PresentationItemType" => "NetSuite\Classes\PresentationItemType",
		"LandedCostSource" => "NetSuite\Classes\LandedCostSource",
		"LandedCostMethod" => "NetSuite\Classes\LandedCostMethod",
		"SitemapPriority" => "NetSuite\Classes\SitemapPriority",
		"TimeItemTimeType" => "NetSuite\Classes\TimeItemTimeType",
		"PermissionCode" => "NetSuite\Classes\PermissionCode",
		"IntercoStatus" => "NetSuite\Classes\IntercoStatus",
		"CurrencySymbolPlacement" => "NetSuite\Classes\CurrencySymbolPlacement",
		"RecurrenceFrequency" => "NetSuite\Classes\RecurrenceFrequency",
		"RecurrenceDow" => "NetSuite\Classes\RecurrenceDow",
		"RecurrenceDowim" => "NetSuite\Classes\RecurrenceDowim",
		"AlcoholRecipientType" => "NetSuite\Classes\AlcoholRecipientType",
		"ShippingCarrier" => "NetSuite\Classes\ShippingCarrier",
		"ItemSource" => "NetSuite\Classes\ItemSource",
		"Address" => "NetSuite\Classes\Address",
		"PresentationItem" => "NetSuite\Classes\PresentationItem",
		"Partners" => "NetSuite\Classes\Partners",
		"LandedCost" => "NetSuite\Classes\LandedCost",
		"LandedCostDataList" => "NetSuite\Classes\LandedCostDataList",
		"LandedCostData" => "NetSuite\Classes\LandedCostData",
		"LandedCostSummary" => "NetSuite\Classes\LandedCostSummary",
		"CustomerSalesTeam" => "NetSuite\Classes\CustomerSalesTeam",
		"TimeItem" => "NetSuite\Classes\TimeItem",
		"InventoryDetail" => "NetSuite\Classes\InventoryDetail",
		"RecurrenceDowMaskList" => "NetSuite\Classes\RecurrenceDowMaskList",
		"AccountingBookDetail" => "NetSuite\Classes\AccountingBookDetail",
		"AccountingBookDetailList" => "NetSuite\Classes\AccountingBookDetailList",
		"InventoryAssignmentList" => "NetSuite\Classes\InventoryAssignmentList",
		"InventoryAssignment" => "NetSuite\Classes\InventoryAssignment",
		"InventoryDetailSearchBasic" => "NetSuite\Classes\InventoryDetailSearchBasic",
		"InventoryDetailSearchRowBasic" => "NetSuite\Classes\InventoryDetailSearchRowBasic",
		"EntitySearchBasic" => "NetSuite\Classes\EntitySearchBasic",
		"EntitySearchRowBasic" => "NetSuite\Classes\EntitySearchRowBasic",
		"ContactSearchBasic" => "NetSuite\Classes\ContactSearchBasic",
		"ContactSearchRowBasic" => "NetSuite\Classes\ContactSearchRowBasic",
		"CustomerSearchBasic" => "NetSuite\Classes\CustomerSearchBasic",
		"CustomerSearchRowBasic" => "NetSuite\Classes\CustomerSearchRowBasic",
		"CalendarEventSearchBasic" => "NetSuite\Classes\CalendarEventSearchBasic",
		"CalendarEventSearchRowBasic" => "NetSuite\Classes\CalendarEventSearchRowBasic",
		"TaskSearchBasic" => "NetSuite\Classes\TaskSearchBasic",
		"TaskSearchRowBasic" => "NetSuite\Classes\TaskSearchRowBasic",
		"OpportunitySearchBasic" => "NetSuite\Classes\OpportunitySearchBasic",
		"OpportunitySearchRowBasic" => "NetSuite\Classes\OpportunitySearchRowBasic",
		"EmployeeSearchBasic" => "NetSuite\Classes\EmployeeSearchBasic",
		"EmployeeSearchRowBasic" => "NetSuite\Classes\EmployeeSearchRowBasic",
		"PhoneCallSearchBasic" => "NetSuite\Classes\PhoneCallSearchBasic",
		"PhoneCallSearchRowBasic" => "NetSuite\Classes\PhoneCallSearchRowBasic",
		"SupportCaseSearchBasic" => "NetSuite\Classes\SupportCaseSearchBasic",
		"SupportCaseSearchRowBasic" => "NetSuite\Classes\SupportCaseSearchRowBasic",
		"MessageSearchBasic" => "NetSuite\Classes\MessageSearchBasic",
		"MessageSearchRowBasic" => "NetSuite\Classes\MessageSearchRowBasic",
		"NoteSearchBasic" => "NetSuite\Classes\NoteSearchBasic",
		"NoteSearchRowBasic" => "NetSuite\Classes\NoteSearchRowBasic",
		"CustomRecordSearchBasic" => "NetSuite\Classes\CustomRecordSearchBasic",
		"CustomRecordSearchRowBasic" => "NetSuite\Classes\CustomRecordSearchRowBasic",
		"AccountSearchBasic" => "NetSuite\Classes\AccountSearchBasic",
		"AccountSearchRowBasic" => "NetSuite\Classes\AccountSearchRowBasic",
		"RevRecScheduleSearchBasic" => "NetSuite\Classes\RevRecScheduleSearchBasic",
		"RevRecScheduleSearchRowBasic" => "NetSuite\Classes\RevRecScheduleSearchRowBasic",
		"RevRecTemplateSearchBasic" => "NetSuite\Classes\RevRecTemplateSearchBasic",
		"RevRecTemplateSearchRowBasic" => "NetSuite\Classes\RevRecTemplateSearchRowBasic",
		"BinSearchBasic" => "NetSuite\Classes\BinSearchBasic",
		"BinSearchRowBasic" => "NetSuite\Classes\BinSearchRowBasic",
		"DepartmentSearchBasic" => "NetSuite\Classes\DepartmentSearchBasic",
		"DepartmentSearchRowBasic" => "NetSuite\Classes\DepartmentSearchRowBasic",
		"LocationSearchBasic" => "NetSuite\Classes\LocationSearchBasic",
		"LocationSearchRowBasic" => "NetSuite\Classes\LocationSearchRowBasic",
		"ClassificationSearchBasic" => "NetSuite\Classes\ClassificationSearchBasic",
		"ClassificationSearchRowBasic" => "NetSuite\Classes\ClassificationSearchRowBasic",
		"TransactionSearchBasic" => "NetSuite\Classes\TransactionSearchBasic",
		"TransactionSearchRowBasic" => "NetSuite\Classes\TransactionSearchRowBasic",
		"ItemSearchBasic" => "NetSuite\Classes\ItemSearchBasic",
		"ItemSearchRowBasic" => "NetSuite\Classes\ItemSearchRowBasic",
		"PartnerSearchBasic" => "NetSuite\Classes\PartnerSearchBasic",
		"PartnerSearchRowBasic" => "NetSuite\Classes\PartnerSearchRowBasic",
		"VendorSearchBasic" => "NetSuite\Classes\VendorSearchBasic",
		"VendorSearchRowBasic" => "NetSuite\Classes\VendorSearchRowBasic",
		"SiteCategorySearchBasic" => "NetSuite\Classes\SiteCategorySearchBasic",
		"SiteCategorySearchRowBasic" => "NetSuite\Classes\SiteCategorySearchRowBasic",
		"TimeBillSearchBasic" => "NetSuite\Classes\TimeBillSearchBasic",
		"TimeBillSearchRowBasic" => "NetSuite\Classes\TimeBillSearchRowBasic",
		"SolutionSearchBasic" => "NetSuite\Classes\SolutionSearchBasic",
		"SolutionSearchRowBasic" => "NetSuite\Classes\SolutionSearchRowBasic",
		"TopicSearchBasic" => "NetSuite\Classes\TopicSearchBasic",
		"TopicSearchRowBasic" => "NetSuite\Classes\TopicSearchRowBasic",
		"SubsidiarySearchBasic" => "NetSuite\Classes\SubsidiarySearchBasic",
		"SubsidiarySearchRowBasic" => "NetSuite\Classes\SubsidiarySearchRowBasic",
		"GiftCertificateSearchBasic" => "NetSuite\Classes\GiftCertificateSearchBasic",
		"GiftCertificateSearchRowBasic" => "NetSuite\Classes\GiftCertificateSearchRowBasic",
		"FolderSearchBasic" => "NetSuite\Classes\FolderSearchBasic",
		"FolderSearchRowBasic" => "NetSuite\Classes\FolderSearchRowBasic",
		"FileSearchBasic" => "NetSuite\Classes\FileSearchBasic",
		"FileSearchRowBasic" => "NetSuite\Classes\FileSearchRowBasic",
		"JobSearchBasic" => "NetSuite\Classes\JobSearchBasic",
		"JobSearchRowBasic" => "NetSuite\Classes\JobSearchRowBasic",
		"IssueSearchBasic" => "NetSuite\Classes\IssueSearchBasic",
		"IssueSearchRowBasic" => "NetSuite\Classes\IssueSearchRowBasic",
		"GroupMemberSearchBasic" => "NetSuite\Classes\GroupMemberSearchBasic",
		"CampaignSearchBasic" => "NetSuite\Classes\CampaignSearchBasic",
		"CampaignSearchRowBasic" => "NetSuite\Classes\CampaignSearchRowBasic",
		"EntityGroupSearchBasic" => "NetSuite\Classes\EntityGroupSearchBasic",
		"EntityGroupSearchRowBasic" => "NetSuite\Classes\EntityGroupSearchRowBasic",
		"PromotionCodeSearchBasic" => "NetSuite\Classes\PromotionCodeSearchBasic",
		"PromotionCodeSearchRowBasic" => "NetSuite\Classes\PromotionCodeSearchRowBasic",
		"BudgetSearchBasic" => "NetSuite\Classes\BudgetSearchBasic",
		"BudgetSearchRowBasic" => "NetSuite\Classes\BudgetSearchRowBasic",
		"ProjectTaskSearchBasic" => "NetSuite\Classes\ProjectTaskSearchBasic",
		"ProjectTaskSearchRowBasic" => "NetSuite\Classes\ProjectTaskSearchRowBasic",
		"ProjectTaskAssignmentSearchBasic" => "NetSuite\Classes\ProjectTaskAssignmentSearchBasic",
		"ProjectTaskAssignmentSearchRowBasic" => "NetSuite\Classes\ProjectTaskAssignmentSearchRowBasic",
		"AccountingPeriodSearchBasic" => "NetSuite\Classes\AccountingPeriodSearchBasic",
		"AccountingPeriodSearchRowBasic" => "NetSuite\Classes\AccountingPeriodSearchRowBasic",
		"ContactCategorySearchBasic" => "NetSuite\Classes\ContactCategorySearchBasic",
		"ContactCategorySearchRowBasic" => "NetSuite\Classes\ContactCategorySearchRowBasic",
		"ContactRoleSearchBasic" => "NetSuite\Classes\ContactRoleSearchBasic",
		"ContactRoleSearchRowBasic" => "NetSuite\Classes\ContactRoleSearchRowBasic",
		"CustomerCategorySearchBasic" => "NetSuite\Classes\CustomerCategorySearchBasic",
		"CustomerCategorySearchRowBasic" => "NetSuite\Classes\CustomerCategorySearchRowBasic",
		"CustomerStatusSearchBasic" => "NetSuite\Classes\CustomerStatusSearchBasic",
		"CustomerStatusSearchRowBasic" => "NetSuite\Classes\CustomerStatusSearchRowBasic",
		"ExpenseCategorySearchBasic" => "NetSuite\Classes\ExpenseCategorySearchBasic",
		"ExpenseCategorySearchRowBasic" => "NetSuite\Classes\ExpenseCategorySearchRowBasic",
		"JobStatusSearchBasic" => "NetSuite\Classes\JobStatusSearchBasic",
		"JobStatusSearchRowBasic" => "NetSuite\Classes\JobStatusSearchRowBasic",
		"JobTypeSearchBasic" => "NetSuite\Classes\JobTypeSearchBasic",
		"JobTypeSearchRowBasic" => "NetSuite\Classes\JobTypeSearchRowBasic",
		"NoteTypeSearchBasic" => "NetSuite\Classes\NoteTypeSearchBasic",
		"NoteTypeSearchRowBasic" => "NetSuite\Classes\NoteTypeSearchRowBasic",
		"PartnerCategorySearchBasic" => "NetSuite\Classes\PartnerCategorySearchBasic",
		"PartnerCategorySearchRowBasic" => "NetSuite\Classes\PartnerCategorySearchRowBasic",
		"PaymentMethodSearchBasic" => "NetSuite\Classes\PaymentMethodSearchBasic",
		"PaymentMethodSearchRowBasic" => "NetSuite\Classes\PaymentMethodSearchRowBasic",
		"PriceLevelSearchBasic" => "NetSuite\Classes\PriceLevelSearchBasic",
		"PriceLevelSearchRowBasic" => "NetSuite\Classes\PriceLevelSearchRowBasic",
		"SalesRoleSearchBasic" => "NetSuite\Classes\SalesRoleSearchBasic",
		"SalesRoleSearchRowBasic" => "NetSuite\Classes\SalesRoleSearchRowBasic",
		"TermSearchBasic" => "NetSuite\Classes\TermSearchBasic",
		"TermSearchRowBasic" => "NetSuite\Classes\TermSearchRowBasic",
		"VendorCategorySearchBasic" => "NetSuite\Classes\VendorCategorySearchBasic",
		"VendorCategorySearchRowBasic" => "NetSuite\Classes\VendorCategorySearchRowBasic",
		"WinLossReasonSearchBasic" => "NetSuite\Classes\WinLossReasonSearchBasic",
		"WinLossReasonSearchRowBasic" => "NetSuite\Classes\WinLossReasonSearchRowBasic",
		"OriginatingLeadSearchBasic" => "NetSuite\Classes\OriginatingLeadSearchBasic",
		"OriginatingLeadSearchRowBasic" => "NetSuite\Classes\OriginatingLeadSearchRowBasic",
		"UnitsTypeSearchBasic" => "NetSuite\Classes\UnitsTypeSearchBasic",
		"UnitsTypeSearchRowBasic" => "NetSuite\Classes\UnitsTypeSearchRowBasic",
		"CustomListSearchBasic" => "NetSuite\Classes\CustomListSearchBasic",
		"CustomListSearchRowBasic" => "NetSuite\Classes\CustomListSearchRowBasic",
		"PricingGroupSearchBasic" => "NetSuite\Classes\PricingGroupSearchBasic",
		"PricingGroupSearchRowBasic" => "NetSuite\Classes\PricingGroupSearchRowBasic",
		"InventoryNumberSearchBasic" => "NetSuite\Classes\InventoryNumberSearchBasic",
		"InventoryNumberSearchRowBasic" => "NetSuite\Classes\InventoryNumberSearchRowBasic",
		"InventoryNumberBinSearchBasic" => "NetSuite\Classes\InventoryNumberBinSearchBasic",
		"InventoryNumberBinSearchRowBasic" => "NetSuite\Classes\InventoryNumberBinSearchRowBasic",
		"ItemBinNumberSearchBasic" => "NetSuite\Classes\ItemBinNumberSearchBasic",
		"ItemBinNumberSearchRowBasic" => "NetSuite\Classes\ItemBinNumberSearchRowBasic",
		"PricingSearchBasic" => "NetSuite\Classes\PricingSearchBasic",
		"PricingSearchRowBasic" => "NetSuite\Classes\PricingSearchRowBasic",
		"NexusSearchBasic" => "NetSuite\Classes\NexusSearchBasic",
		"NexusSearchRowBasic" => "NetSuite\Classes\NexusSearchRowBasic",
		"OtherNameCategorySearchBasic" => "NetSuite\Classes\OtherNameCategorySearchBasic",
		"OtherNameCategorySearchRowBasic" => "NetSuite\Classes\OtherNameCategorySearchRowBasic",
		"CustomerMessageSearchBasic" => "NetSuite\Classes\CustomerMessageSearchBasic",
		"CustomerMessageSearchRowBasic" => "NetSuite\Classes\CustomerMessageSearchRowBasic",
		"ItemDemandPlanSearchBasic" => "NetSuite\Classes\ItemDemandPlanSearchBasic",
		"ItemDemandPlanSearchRowBasic" => "NetSuite\Classes\ItemDemandPlanSearchRowBasic",
		"ItemSupplyPlanSearchBasic" => "NetSuite\Classes\ItemSupplyPlanSearchBasic",
		"ItemSupplyPlanSearchRowBasic" => "NetSuite\Classes\ItemSupplyPlanSearchRowBasic",
		"CurrencyRateSearchBasic" => "NetSuite\Classes\CurrencyRateSearchBasic",
		"CurrencyRateSearchRowBasic" => "NetSuite\Classes\CurrencyRateSearchRowBasic",
		"ItemRevisionSearchBasic" => "NetSuite\Classes\ItemRevisionSearchBasic",
		"ItemRevisionSearchRowBasic" => "NetSuite\Classes\ItemRevisionSearchRowBasic",
		"CouponCodeSearchBasic" => "NetSuite\Classes\CouponCodeSearchBasic",
		"CouponCodeSearchRowBasic" => "NetSuite\Classes\CouponCodeSearchRowBasic",
		"PayrollItemSearchBasic" => "NetSuite\Classes\PayrollItemSearchBasic",
		"PayrollItemSearchRowBasic" => "NetSuite\Classes\PayrollItemSearchRowBasic",
		"ManufacturingCostTemplateSearchBasic" => "NetSuite\Classes\ManufacturingCostTemplateSearchBasic",
		"ManufacturingCostTemplateSearchRowBasic" => "NetSuite\Classes\ManufacturingCostTemplateSearchRowBasic",
		"ManufacturingRoutingSearchBasic" => "NetSuite\Classes\ManufacturingRoutingSearchBasic",
		"ManufacturingRoutingSearchRowBasic" => "NetSuite\Classes\ManufacturingRoutingSearchRowBasic",
		"ManufacturingOperationTaskSearchBasic" => "NetSuite\Classes\ManufacturingOperationTaskSearchBasic",
		"ManufacturingOperationTaskSearchRowBasic" => "NetSuite\Classes\ManufacturingOperationTaskSearchRowBasic",
		"ResourceAllocationSearchBasic" => "NetSuite\Classes\ResourceAllocationSearchBasic",
		"ResourceAllocationSearchRowBasic" => "NetSuite\Classes\ResourceAllocationSearchRowBasic",
		"CustomSearchJoin" => "NetSuite\Classes\CustomSearchJoin",
		"CustomSearchRowBasic" => "NetSuite\Classes\CustomSearchRowBasic",
		"ChargeSearchBasic" => "NetSuite\Classes\ChargeSearchBasic",
		"ChargeSearchRowBasic" => "NetSuite\Classes\ChargeSearchRowBasic",
		"BillingScheduleSearchBasic" => "NetSuite\Classes\BillingScheduleSearchBasic",
		"BillingScheduleSearchRowBasic" => "NetSuite\Classes\BillingScheduleSearchRowBasic",
		"GlobalAccountMappingSearchBasic" => "NetSuite\Classes\GlobalAccountMappingSearchBasic",
		"GlobalAccountMappingSearchRowBasic" => "NetSuite\Classes\GlobalAccountMappingSearchRowBasic",
		"ItemAccountMappingSearchBasic" => "NetSuite\Classes\ItemAccountMappingSearchBasic",
		"ItemAccountMappingSearchRowBasic" => "NetSuite\Classes\ItemAccountMappingSearchRowBasic",
		"TimeEntrySearchBasic" => "NetSuite\Classes\TimeEntrySearchBasic",
		"TimeEntrySearchRowBasic" => "NetSuite\Classes\TimeEntrySearchRowBasic",
		"TimeSheetSearchBasic" => "NetSuite\Classes\TimeSheetSearchBasic",
		"TimeSheetSearchRowBasic" => "NetSuite\Classes\TimeSheetSearchRowBasic",
		"AccountingTransactionSearchBasic" => "NetSuite\Classes\AccountingTransactionSearchBasic",
		"AccountingTransactionSearchRowBasic" => "NetSuite\Classes\AccountingTransactionSearchRowBasic",
		"AddressSearchBasic" => "NetSuite\Classes\AddressSearchBasic",
		"AddressSearchRowBasic" => "NetSuite\Classes\AddressSearchRowBasic",
		"BillingAccountSearchBasic" => "NetSuite\Classes\BillingAccountSearchBasic",
		"BillingAccountSearchRowBasic" => "NetSuite\Classes\BillingAccountSearchRowBasic",
		"FairValuePriceSearchBasic" => "NetSuite\Classes\FairValuePriceSearchBasic",
		"FairValuePriceSearchRowBasic" => "NetSuite\Classes\FairValuePriceSearchRowBasic",
		"UsageSearchBasic" => "NetSuite\Classes\UsageSearchBasic",
		"UsageSearchRowBasic" => "NetSuite\Classes\UsageSearchRowBasic",
		"CostCategorySearchBasic" => "NetSuite\Classes\CostCategorySearchBasic",
		"CostCategorySearchRowBasic" => "NetSuite\Classes\CostCategorySearchRowBasic",
		"ConsolidatedExchangeRateSearchBasic" => "NetSuite\Classes\ConsolidatedExchangeRateSearchBasic",
		"ConsolidatedExchangeRateSearchRowBasic" => "NetSuite\Classes\ConsolidatedExchangeRateSearchRowBasic",
		"TaxDetails" => "NetSuite\Classes\TaxDetails",
		"TaxDetailsList" => "NetSuite\Classes\TaxDetailsList",
		"TaxDetailSearchBasic" => "NetSuite\Classes\TaxDetailSearchBasic",
		"TaxDetailSearchRowBasic" => "NetSuite\Classes\TaxDetailSearchRowBasic",
		"TaxGroupSearchBasic" => "NetSuite\Classes\TaxGroupSearchBasic",
		"TaxGroupSearchRowBasic" => "NetSuite\Classes\TaxGroupSearchRowBasic",
		"SalesTaxItemSearchBasic" => "NetSuite\Classes\SalesTaxItemSearchBasic",
		"SalesTaxItemSearchRowBasic" => "NetSuite\Classes\SalesTaxItemSearchRowBasic",
		"TaxTypeSearchBasic" => "NetSuite\Classes\TaxTypeSearchBasic",
		"TaxTypeSearchRowBasic" => "NetSuite\Classes\TaxTypeSearchRowBasic",
		"CalendarEventAccessLevel" => "NetSuite\Classes\CalendarEventAccessLevel",
		"CalendarEventAttendeeAttendance" => "NetSuite\Classes\CalendarEventAttendeeAttendance",
		"CalendarEventReminderMinutes" => "NetSuite\Classes\CalendarEventReminderMinutes",
		"CalendarEventReminderType" => "NetSuite\Classes\CalendarEventReminderType",
		"CalendarEventStatus" => "NetSuite\Classes\CalendarEventStatus",
		"TaskPriority" => "NetSuite\Classes\TaskPriority",
		"TaskReminderMinutes" => "NetSuite\Classes\TaskReminderMinutes",
		"TaskReminderType" => "NetSuite\Classes\TaskReminderType",
		"TaskStatus" => "NetSuite\Classes\TaskStatus",
		"PhoneCallPriority" => "NetSuite\Classes\PhoneCallPriority",
		"PhoneCallReminderMinutes" => "NetSuite\Classes\PhoneCallReminderMinutes",
		"PhoneCallReminderType" => "NetSuite\Classes\PhoneCallReminderType",
		"PhoneCallStatus" => "NetSuite\Classes\PhoneCallStatus",
		"ProjectTaskPriority" => "NetSuite\Classes\ProjectTaskPriority",
		"ProjectTaskStatus" => "NetSuite\Classes\ProjectTaskStatus",
		"ProjectTaskConstraintType" => "NetSuite\Classes\ProjectTaskConstraintType",
		"ProjectTaskPredecessorPredecessorType" => "NetSuite\Classes\ProjectTaskPredecessorPredecessorType",
		"ResourceAllocationAllocationUnit" => "NetSuite\Classes\ResourceAllocationAllocationUnit",
		"ResourceAllocationApprovalStatus" => "NetSuite\Classes\ResourceAllocationApprovalStatus",
		"CalendarEvent" => "NetSuite\Classes\CalendarEvent",
		"ExclusionDateList" => "NetSuite\Classes\ExclusionDateList",
		"CalendarEventAttendee" => "NetSuite\Classes\CalendarEventAttendee",
		"CalendarEventAttendeeList" => "NetSuite\Classes\CalendarEventAttendeeList",
		"CalendarEventResource" => "NetSuite\Classes\CalendarEventResource",
		"CalendarEventResourceList" => "NetSuite\Classes\CalendarEventResourceList",
		"CalendarEventSearch" => "NetSuite\Classes\CalendarEventSearch",
		"CalendarEventSearchAdvanced" => "NetSuite\Classes\CalendarEventSearchAdvanced",
		"CalendarEventSearchRow" => "NetSuite\Classes\CalendarEventSearchRow",
		"Task" => "NetSuite\Classes\Task",
		"TaskContact" => "NetSuite\Classes\TaskContact",
		"TaskContactList" => "NetSuite\Classes\TaskContactList",
		"TaskSearch" => "NetSuite\Classes\TaskSearch",
		"TaskSearchAdvanced" => "NetSuite\Classes\TaskSearchAdvanced",
		"TaskSearchRow" => "NetSuite\Classes\TaskSearchRow",
		"PhoneCall" => "NetSuite\Classes\PhoneCall",
		"PhoneCallContact" => "NetSuite\Classes\PhoneCallContact",
		"PhoneCallContactList" => "NetSuite\Classes\PhoneCallContactList",
		"PhoneCallSearch" => "NetSuite\Classes\PhoneCallSearch",
		"PhoneCallSearchAdvanced" => "NetSuite\Classes\PhoneCallSearchAdvanced",
		"PhoneCallSearchRow" => "NetSuite\Classes\PhoneCallSearchRow",
		"ProjectTask" => "NetSuite\Classes\ProjectTask",
		"ProjectTaskPredecessor" => "NetSuite\Classes\ProjectTaskPredecessor",
		"ProjectTaskPredecessorList" => "NetSuite\Classes\ProjectTaskPredecessorList",
		"ProjectTaskAssignee" => "NetSuite\Classes\ProjectTaskAssignee",
		"ProjectTaskAssigneeList" => "NetSuite\Classes\ProjectTaskAssigneeList",
		"ProjectTaskSearch" => "NetSuite\Classes\ProjectTaskSearch",
		"ProjectTaskSearchAdvanced" => "NetSuite\Classes\ProjectTaskSearchAdvanced",
		"ProjectTaskSearchRow" => "NetSuite\Classes\ProjectTaskSearchRow",
		"PhoneCallTimeItemList" => "NetSuite\Classes\PhoneCallTimeItemList",
		"CalendarEventTimeItemList" => "NetSuite\Classes\CalendarEventTimeItemList",
		"TaskTimeItemList" => "NetSuite\Classes\TaskTimeItemList",
		"ProjectTaskTimeItemList" => "NetSuite\Classes\ProjectTaskTimeItemList",
		"ResourceAllocation" => "NetSuite\Classes\ResourceAllocation",
		"ResourceAllocationSearch" => "NetSuite\Classes\ResourceAllocationSearch",
		"ResourceAllocationSearchAdvanced" => "NetSuite\Classes\ResourceAllocationSearchAdvanced",
		"ResourceAllocationSearchRow" => "NetSuite\Classes\ResourceAllocationSearchRow",
		"NoteDirection" => "NetSuite\Classes\NoteDirection",
		"MessageMessageType" => "NetSuite\Classes\MessageMessageType",
		"File" => "NetSuite\Classes\File",
		"FileSiteCategory" => "NetSuite\Classes\FileSiteCategory",
		"FileSiteCategoryList" => "NetSuite\Classes\FileSiteCategoryList",
		"FileSearch" => "NetSuite\Classes\FileSearch",
		"FileSearchAdvanced" => "NetSuite\Classes\FileSearchAdvanced",
		"FileSearchRow" => "NetSuite\Classes\FileSearchRow",
		"Folder" => "NetSuite\Classes\Folder",
		"FolderSearch" => "NetSuite\Classes\FolderSearch",
		"FolderSearchAdvanced" => "NetSuite\Classes\FolderSearchAdvanced",
		"FolderSearchRow" => "NetSuite\Classes\FolderSearchRow",
		"Note" => "NetSuite\Classes\Note",
		"NoteSearch" => "NetSuite\Classes\NoteSearch",
		"NoteSearchAdvanced" => "NetSuite\Classes\NoteSearchAdvanced",
		"NoteSearchRow" => "NetSuite\Classes\NoteSearchRow",
		"Message" => "NetSuite\Classes\Message",
		"MessageMediaItemList" => "NetSuite\Classes\MessageMediaItemList",
		"MessageSearch" => "NetSuite\Classes\MessageSearch",
		"MessageSearchAdvanced" => "NetSuite\Classes\MessageSearchAdvanced",
		"MessageSearchRow" => "NetSuite\Classes\MessageSearchRow",
		"EntityType" => "NetSuite\Classes\EntityType",
		"CustomerStatusStage" => "NetSuite\Classes\CustomerStatusStage",
		"ContactType" => "NetSuite\Classes\ContactType",
		"CustomerStage" => "NetSuite\Classes\CustomerStage",
		"CustomerCreditHoldOverride" => "NetSuite\Classes\CustomerCreditHoldOverride",
		"CustomerMonthlyClosing" => "NetSuite\Classes\CustomerMonthlyClosing",
		"EmailPreference" => "NetSuite\Classes\EmailPreference",
		"EntityGroupType" => "NetSuite\Classes\EntityGroupType",
		"TaxFractionUnit" => "NetSuite\Classes\TaxFractionUnit",
		"TaxRounding" => "NetSuite\Classes\TaxRounding",
		"JobBillingType" => "NetSuite\Classes\JobBillingType",
		"PartnerOtherRelationships" => "NetSuite\Classes\PartnerOtherRelationships",
		"CustomerOtherRelationships" => "NetSuite\Classes\CustomerOtherRelationships",
		"VendorOtherRelationships" => "NetSuite\Classes\VendorOtherRelationships",
		"CustomerNegativeNumberFormat" => "NetSuite\Classes\CustomerNegativeNumberFormat",
		"CustomerNumberFormat" => "NetSuite\Classes\CustomerNumberFormat",
		"BillingAccountFrequency" => "NetSuite\Classes\BillingAccountFrequency",
		"Subscriptions" => "NetSuite\Classes\Subscriptions",
		"SubscriptionsList" => "NetSuite\Classes\SubscriptionsList",
		"Contact" => "NetSuite\Classes\Contact",
		"CategoryList" => "NetSuite\Classes\CategoryList",
		"ContactAddressbook" => "NetSuite\Classes\ContactAddressbook",
		"ContactAddressbookList" => "NetSuite\Classes\ContactAddressbookList",
		"ContactSearch" => "NetSuite\Classes\ContactSearch",
		"ContactSearchAdvanced" => "NetSuite\Classes\ContactSearchAdvanced",
		"ContactSearchRow" => "NetSuite\Classes\ContactSearchRow",
		"Customer" => "NetSuite\Classes\Customer",
		"CustomerDownload" => "NetSuite\Classes\CustomerDownload",
		"CustomerDownloadList" => "NetSuite\Classes\CustomerDownloadList",
		"ContactAccessRoles" => "NetSuite\Classes\ContactAccessRoles",
		"ContactAccessRolesList" => "NetSuite\Classes\ContactAccessRolesList",
		"CustomerSalesTeamList" => "NetSuite\Classes\CustomerSalesTeamList",
		"CustomerAddressbook" => "NetSuite\Classes\CustomerAddressbook",
		"CustomerAddressbookList" => "NetSuite\Classes\CustomerAddressbookList",
		"CustomerCreditCards" => "NetSuite\Classes\CustomerCreditCards",
		"CustomerCreditCardsList" => "NetSuite\Classes\CustomerCreditCardsList",
		"CustomerGroupPricing" => "NetSuite\Classes\CustomerGroupPricing",
		"CustomerGroupPricingList" => "NetSuite\Classes\CustomerGroupPricingList",
		"CustomerItemPricing" => "NetSuite\Classes\CustomerItemPricing",
		"CustomerItemPricingList" => "NetSuite\Classes\CustomerItemPricingList",
		"CustomerPartnersList" => "NetSuite\Classes\CustomerPartnersList",
		"CustomerSearch" => "NetSuite\Classes\CustomerSearch",
		"CustomerSearchAdvanced" => "NetSuite\Classes\CustomerSearchAdvanced",
		"CustomerSearchRow" => "NetSuite\Classes\CustomerSearchRow",
		"CustomerStatus" => "NetSuite\Classes\CustomerStatus",
		"Partner" => "NetSuite\Classes\Partner",
		"PartnerPromoCode" => "NetSuite\Classes\PartnerPromoCode",
		"PartnerPromoCodeList" => "NetSuite\Classes\PartnerPromoCodeList",
		"PartnerAddressbook" => "NetSuite\Classes\PartnerAddressbook",
		"PartnerAddressbookList" => "NetSuite\Classes\PartnerAddressbookList",
		"PartnerSearch" => "NetSuite\Classes\PartnerSearch",
		"PartnerSearchAdvanced" => "NetSuite\Classes\PartnerSearchAdvanced",
		"PartnerSearchRow" => "NetSuite\Classes\PartnerSearchRow",
		"Vendor" => "NetSuite\Classes\Vendor",
		"VendorPricingSchedule" => "NetSuite\Classes\VendorPricingSchedule",
		"VendorPricingScheduleList" => "NetSuite\Classes\VendorPricingScheduleList",
		"VendorAddressbook" => "NetSuite\Classes\VendorAddressbook",
		"VendorAddressbookList" => "NetSuite\Classes\VendorAddressbookList",
		"VendorRoles" => "NetSuite\Classes\VendorRoles",
		"VendorRolesList" => "NetSuite\Classes\VendorRolesList",
		"VendorSearch" => "NetSuite\Classes\VendorSearch",
		"VendorSearchAdvanced" => "NetSuite\Classes\VendorSearchAdvanced",
		"VendorSearchRow" => "NetSuite\Classes\VendorSearchRow",
		"EntityGroup" => "NetSuite\Classes\EntityGroup",
		"EntityGroupSearch" => "NetSuite\Classes\EntityGroupSearch",
		"EntityGroupSearchAdvanced" => "NetSuite\Classes\EntityGroupSearchAdvanced",
		"EntityGroupSearchRow" => "NetSuite\Classes\EntityGroupSearchRow",
		"Job" => "NetSuite\Classes\Job",
		"JobAddressbook" => "NetSuite\Classes\JobAddressbook",
		"JobAddressbookList" => "NetSuite\Classes\JobAddressbookList",
		"JobResources" => "NetSuite\Classes\JobResources",
		"JobResourcesList" => "NetSuite\Classes\JobResourcesList",
		"JobMilestones" => "NetSuite\Classes\JobMilestones",
		"JobMilestonesList" => "NetSuite\Classes\JobMilestonesList",
		"JobCreditCards" => "NetSuite\Classes\JobCreditCards",
		"JobCreditCardsList" => "NetSuite\Classes\JobCreditCardsList",
		"JobSearch" => "NetSuite\Classes\JobSearch",
		"JobSearchAdvanced" => "NetSuite\Classes\JobSearchAdvanced",
		"JobSearchRow" => "NetSuite\Classes\JobSearchRow",
		"JobType" => "NetSuite\Classes\JobType",
		"JobStatus" => "NetSuite\Classes\JobStatus",
		"CustomerStatusSearch" => "NetSuite\Classes\CustomerStatusSearch",
		"CustomerStatusSearchAdvanced" => "NetSuite\Classes\CustomerStatusSearchAdvanced",
		"CustomerStatusSearchRow" => "NetSuite\Classes\CustomerStatusSearchRow",
		"JobStatusSearch" => "NetSuite\Classes\JobStatusSearch",
		"JobStatusSearchAdvanced" => "NetSuite\Classes\JobStatusSearchAdvanced",
		"JobStatusSearchRow" => "NetSuite\Classes\JobStatusSearchRow",
		"JobTypeSearch" => "NetSuite\Classes\JobTypeSearch",
		"JobTypeSearchAdvanced" => "NetSuite\Classes\JobTypeSearchAdvanced",
		"JobTypeSearchRow" => "NetSuite\Classes\JobTypeSearchRow",
		"OriginatingLeadSearch" => "NetSuite\Classes\OriginatingLeadSearch",
		"OriginatingLeadSearchRow" => "NetSuite\Classes\OriginatingLeadSearchRow",
		"CustomerCurrency" => "NetSuite\Classes\CustomerCurrency",
		"CustomerCurrencyList" => "NetSuite\Classes\CustomerCurrencyList",
		"VendorCurrency" => "NetSuite\Classes\VendorCurrency",
		"VendorCurrencyList" => "NetSuite\Classes\VendorCurrencyList",
		"JobPlStatement" => "NetSuite\Classes\JobPlStatement",
		"JobPlStatementList" => "NetSuite\Classes\JobPlStatementList",
		"BillingAccount" => "NetSuite\Classes\BillingAccount",
		"BillingAccountSearch" => "NetSuite\Classes\BillingAccountSearch",
		"BillingAccountSearchAdvanced" => "NetSuite\Classes\BillingAccountSearchAdvanced",
		"BillingAccountSearchRow" => "NetSuite\Classes\BillingAccountSearchRow",
		"JobPercentCompleteOverride" => "NetSuite\Classes\JobPercentCompleteOverride",
		"JobPercentCompleteOverrideList" => "NetSuite\Classes\JobPercentCompleteOverrideList",
		"SupportCaseStatusStage" => "NetSuite\Classes\SupportCaseStatusStage",
		"SupportCaseStage" => "NetSuite\Classes\SupportCaseStage",
		"SolutionStatus" => "NetSuite\Classes\SolutionStatus",
		"IssueEventStatus" => "NetSuite\Classes\IssueEventStatus",
		"IssueTrackCode" => "NetSuite\Classes\IssueTrackCode",
		"IssueRelationship" => "NetSuite\Classes\IssueRelationship",
		"SupportCase" => "NetSuite\Classes\SupportCase",
		"EmailEmployeesList" => "NetSuite\Classes\EmailEmployeesList",
		"SupportCaseEscalateTo" => "NetSuite\Classes\SupportCaseEscalateTo",
		"SupportCaseEscalateToList" => "NetSuite\Classes\SupportCaseEscalateToList",
		"SupportCaseSolutions" => "NetSuite\Classes\SupportCaseSolutions",
		"SupportCaseSolutionsList" => "NetSuite\Classes\SupportCaseSolutionsList",
		"SupportCaseTimeItemList" => "NetSuite\Classes\SupportCaseTimeItemList",
		"SupportCaseSearch" => "NetSuite\Classes\SupportCaseSearch",
		"SupportCaseSearchAdvanced" => "NetSuite\Classes\SupportCaseSearchAdvanced",
		"SupportCaseSearchRow" => "NetSuite\Classes\SupportCaseSearchRow",
		"SupportCaseStatus" => "NetSuite\Classes\SupportCaseStatus",
		"SupportCaseType" => "NetSuite\Classes\SupportCaseType",
		"SupportCaseOrigin" => "NetSuite\Classes\SupportCaseOrigin",
		"SupportCaseIssue" => "NetSuite\Classes\SupportCaseIssue",
		"SupportCasePriority" => "NetSuite\Classes\SupportCasePriority",
		"Solution" => "NetSuite\Classes\Solution",
		"SolutionTopics" => "NetSuite\Classes\SolutionTopics",
		"SolutionTopicsList" => "NetSuite\Classes\SolutionTopicsList",
		"Solutions" => "NetSuite\Classes\Solutions",
		"SolutionsList" => "NetSuite\Classes\SolutionsList",
		"SolutionSearch" => "NetSuite\Classes\SolutionSearch",
		"SolutionSearchAdvanced" => "NetSuite\Classes\SolutionSearchAdvanced",
		"SolutionSearchRow" => "NetSuite\Classes\SolutionSearchRow",
		"Topic" => "NetSuite\Classes\Topic",
		"TopicSolution" => "NetSuite\Classes\TopicSolution",
		"TopicSolutionList" => "NetSuite\Classes\TopicSolutionList",
		"TopicSearch" => "NetSuite\Classes\TopicSearch",
		"TopicSearchAdvanced" => "NetSuite\Classes\TopicSearchAdvanced",
		"TopicSearchRow" => "NetSuite\Classes\TopicSearchRow",
		"Issue" => "NetSuite\Classes\Issue",
		"IssueVersion" => "NetSuite\Classes\IssueVersion",
		"IssueVersionList" => "NetSuite\Classes\IssueVersionList",
		"IssueSearch" => "NetSuite\Classes\IssueSearch",
		"IssueSearchAdvanced" => "NetSuite\Classes\IssueSearchAdvanced",
		"IssueSearchRow" => "NetSuite\Classes\IssueSearchRow",
		"IssueRelatedIssues" => "NetSuite\Classes\IssueRelatedIssues",
		"IssueRelatedIssuesList" => "NetSuite\Classes\IssueRelatedIssuesList",
		"CurrencyLocale" => "NetSuite\Classes\CurrencyLocale",
		"AccountType" => "NetSuite\Classes\AccountType",
		"ItemCostingMethod" => "NetSuite\Classes\ItemCostingMethod",
		"ItemProductFeed" => "NetSuite\Classes\ItemProductFeed",
		"ItemType" => "NetSuite\Classes\ItemType",
		"ItemWeightUnit" => "NetSuite\Classes\ItemWeightUnit",
		"ItemPreferenceCriterion" => "NetSuite\Classes\ItemPreferenceCriterion",
		"ItemOverallQuantityPricingType" => "NetSuite\Classes\ItemOverallQuantityPricingType",
		"ScheduleBCode" => "NetSuite\Classes\ScheduleBCode",
		"ItemSubType" => "NetSuite\Classes\ItemSubType",
		"CurrencyCurrencyPrecision" => "NetSuite\Classes\CurrencyCurrencyPrecision",
		"CurrencyFxRateUpdateTimezone" => "NetSuite\Classes\CurrencyFxRateUpdateTimezone",
		"SalesTaxItemAvailable" => "NetSuite\Classes\SalesTaxItemAvailable",
		"ItemEbayAuctionDuration" => "NetSuite\Classes\ItemEbayAuctionDuration",
		"ItemOutOfStockBehavior" => "NetSuite\Classes\ItemOutOfStockBehavior",
		"ItemEbayRelistingOption" => "NetSuite\Classes\ItemEbayRelistingOption",
		"ConsolidatedRate" => "NetSuite\Classes\ConsolidatedRate",
		"CashFlowRateType" => "NetSuite\Classes\CashFlowRateType",
		"GeneralRateType" => "NetSuite\Classes\GeneralRateType",
		"ItemMatrixType" => "NetSuite\Classes\ItemMatrixType",
		"ItemDemandSource" => "NetSuite\Classes\ItemDemandSource",
		"ItemSupplyLotSizingMethod" => "NetSuite\Classes\ItemSupplyLotSizingMethod",
		"ItemSupplyType" => "NetSuite\Classes\ItemSupplyType",
		"ItemSupplyReplenishmentMethod" => "NetSuite\Classes\ItemSupplyReplenishmentMethod",
		"RevRecScheduleRecogIntervalSrc" => "NetSuite\Classes\RevRecScheduleRecogIntervalSrc",
		"RevRecScheduleRecurrenceType" => "NetSuite\Classes\RevRecScheduleRecurrenceType",
		"RevRecScheduleAmortizationType" => "NetSuite\Classes\RevRecScheduleAmortizationType",
		"RevRecScheduleAmortizationStatus" => "NetSuite\Classes\RevRecScheduleAmortizationStatus",
		"CostCategoryItemCostType" => "NetSuite\Classes\CostCategoryItemCostType",
		"ItemAtpMethod" => "NetSuite\Classes\ItemAtpMethod",
		"AssemblyItemEffectiveBomControl" => "NetSuite\Classes\AssemblyItemEffectiveBomControl",
		"ItemInvtClassification" => "NetSuite\Classes\ItemInvtClassification",
		"PeriodicLotSizeType" => "NetSuite\Classes\PeriodicLotSizeType",
		"HazmatPackingGroup" => "NetSuite\Classes\HazmatPackingGroup",
		"TaxAcctType" => "NetSuite\Classes\TaxAcctType",
		"ItemOverheadType" => "NetSuite\Classes\ItemOverheadType",
		"ItemCostAccountingStatus" => "NetSuite\Classes\ItemCostAccountingStatus",
		"BillingScheduleRecurrenceRecurrenceUnits" => "NetSuite\Classes\BillingScheduleRecurrenceRecurrenceUnits",
		"BillingScheduleType" => "NetSuite\Classes\BillingScheduleType",
		"BillingScheduleFrequency" => "NetSuite\Classes\BillingScheduleFrequency",
		"ItemAccountMappingItemAccount" => "NetSuite\Classes\ItemAccountMappingItemAccount",
		"AccountingBookStatus" => "NetSuite\Classes\AccountingBookStatus",
		"BillingScheduleRepeatEvery" => "NetSuite\Classes\BillingScheduleRepeatEvery",
		"BillingScheduleMonthDow" => "NetSuite\Classes\BillingScheduleMonthDow",
		"BillingScheduleYearMonth" => "NetSuite\Classes\BillingScheduleYearMonth",
		"BillingScheduleYearDow" => "NetSuite\Classes\BillingScheduleYearDow",
		"BillingScheduleYearDowim" => "NetSuite\Classes\BillingScheduleYearDowim",
		"BillingScheduleYearDowimMonth" => "NetSuite\Classes\BillingScheduleYearDowimMonth",
		"BillingScheduleMonthDowim" => "NetSuite\Classes\BillingScheduleMonthDowim",
		"BillingScheduleRecurrenceMode" => "NetSuite\Classes\BillingScheduleRecurrenceMode",
		"InventoryItemFraudRisk" => "NetSuite\Classes\InventoryItemFraudRisk",
		"BillingScheduleRecurrencePattern" => "NetSuite\Classes\BillingScheduleRecurrencePattern",
		"ItemCreateRevenuePlansOn" => "NetSuite\Classes\ItemCreateRevenuePlansOn",
		"LocationTimeZone" => "NetSuite\Classes\LocationTimeZone",
		"FairValuePriceFairValueRangePolicy" => "NetSuite\Classes\FairValuePriceFairValueRangePolicy",
		"LocationGeolocationMethod" => "NetSuite\Classes\LocationGeolocationMethod",
		"LocationAutoAssignmentRegionSetting" => "NetSuite\Classes\LocationAutoAssignmentRegionSetting",
		"LocationType" => "NetSuite\Classes\LocationType",
		"ClassTranslation" => "NetSuite\Classes\ClassTranslation",
		"ClassTranslationList" => "NetSuite\Classes\ClassTranslationList",
		"ContactCategory" => "NetSuite\Classes\ContactCategory",
		"CustomerCategory" => "NetSuite\Classes\CustomerCategory",
		"SalesRole" => "NetSuite\Classes\SalesRole",
		"PriceLevel" => "NetSuite\Classes\PriceLevel",
		"WinLossReason" => "NetSuite\Classes\WinLossReason",
		"Term" => "NetSuite\Classes\Term",
		"NoteType" => "NetSuite\Classes\NoteType",
		"PaymentMethod" => "NetSuite\Classes\PaymentMethod",
		"LeadSource" => "NetSuite\Classes\LeadSource",
		"Price" => "NetSuite\Classes\Price",
		"PriceList" => "NetSuite\Classes\PriceList",
		"Pricing" => "NetSuite\Classes\Pricing",
		"PricingMatrix" => "NetSuite\Classes\PricingMatrix",
		"Rate" => "NetSuite\Classes\Rate",
		"RateList" => "NetSuite\Classes\RateList",
		"BillingRates" => "NetSuite\Classes\BillingRates",
		"BillingRatesMatrix" => "NetSuite\Classes\BillingRatesMatrix",
		"Translation" => "NetSuite\Classes\Translation",
		"TranslationList" => "NetSuite\Classes\TranslationList",
		"ItemOptionsList" => "NetSuite\Classes\ItemOptionsList",
		"ItemVendor" => "NetSuite\Classes\ItemVendor",
		"ItemVendorList" => "NetSuite\Classes\ItemVendorList",
		"SiteCategory" => "NetSuite\Classes\SiteCategory",
		"SiteCategoryList" => "NetSuite\Classes\SiteCategoryList",
		"ProductFeedList" => "NetSuite\Classes\ProductFeedList",
		"ItemMember" => "NetSuite\Classes\ItemMember",
		"ItemMemberList" => "NetSuite\Classes\ItemMemberList",
		"InventoryItem" => "NetSuite\Classes\InventoryItem",
		"MatrixOptionList" => "NetSuite\Classes\MatrixOptionList",
		"InventoryItemBinNumber" => "NetSuite\Classes\InventoryItemBinNumber",
		"InventoryItemBinNumberList" => "NetSuite\Classes\InventoryItemBinNumberList",
		"InventoryItemLocations" => "NetSuite\Classes\InventoryItemLocations",
		"InventoryItemLocationsList" => "NetSuite\Classes\InventoryItemLocationsList",
		"PresentationItemList" => "NetSuite\Classes\PresentationItemList",
		"DescriptionItem" => "NetSuite\Classes\DescriptionItem",
		"DiscountItem" => "NetSuite\Classes\DiscountItem",
		"DownloadItem" => "NetSuite\Classes\DownloadItem",
		"MarkupItem" => "NetSuite\Classes\MarkupItem",
		"PaymentItem" => "NetSuite\Classes\PaymentItem",
		"SubtotalItem" => "NetSuite\Classes\SubtotalItem",
		"NonInventoryPurchaseItem" => "NetSuite\Classes\NonInventoryPurchaseItem",
		"NonInventorySaleItem" => "NetSuite\Classes\NonInventorySaleItem",
		"NonInventoryResaleItem" => "NetSuite\Classes\NonInventoryResaleItem",
		"OtherChargeResaleItem" => "NetSuite\Classes\OtherChargeResaleItem",
		"OtherChargePurchaseItem" => "NetSuite\Classes\OtherChargePurchaseItem",
		"ServiceResaleItem" => "NetSuite\Classes\ServiceResaleItem",
		"ServicePurchaseItem" => "NetSuite\Classes\ServicePurchaseItem",
		"ServiceSaleItem" => "NetSuite\Classes\ServiceSaleItem",
		"OtherChargeSaleItem" => "NetSuite\Classes\OtherChargeSaleItem",
		"Currency" => "NetSuite\Classes\Currency",
		"ExpenseCategory" => "NetSuite\Classes\ExpenseCategory",
		"Account" => "NetSuite\Classes\Account",
		"AccountSearch" => "NetSuite\Classes\AccountSearch",
		"AccountSearchAdvanced" => "NetSuite\Classes\AccountSearchAdvanced",
		"AccountSearchRow" => "NetSuite\Classes\AccountSearchRow",
		"Department" => "NetSuite\Classes\Department",
		"DepartmentSearch" => "NetSuite\Classes\DepartmentSearch",
		"DepartmentSearchAdvanced" => "NetSuite\Classes\DepartmentSearchAdvanced",
		"DepartmentSearchRow" => "NetSuite\Classes\DepartmentSearchRow",
		"Classification" => "NetSuite\Classes\Classification",
		"ClassificationSearch" => "NetSuite\Classes\ClassificationSearch",
		"ClassificationSearchAdvanced" => "NetSuite\Classes\ClassificationSearchAdvanced",
		"ClassificationSearchRow" => "NetSuite\Classes\ClassificationSearchRow",
		"Location" => "NetSuite\Classes\Location",
		"LocationSearch" => "NetSuite\Classes\LocationSearch",
		"LocationSearchAdvanced" => "NetSuite\Classes\LocationSearchAdvanced",
		"LocationSearchRow" => "NetSuite\Classes\LocationSearchRow",
		"UnitsType" => "NetSuite\Classes\UnitsType",
		"UnitsTypeUom" => "NetSuite\Classes\UnitsTypeUom",
		"UnitsTypeUomList" => "NetSuite\Classes\UnitsTypeUomList",
		"ItemSearch" => "NetSuite\Classes\ItemSearch",
		"ItemSearchAdvanced" => "NetSuite\Classes\ItemSearchAdvanced",
		"ItemSearchRow" => "NetSuite\Classes\ItemSearchRow",
		"ContactRole" => "NetSuite\Classes\ContactRole",
		"Bin" => "NetSuite\Classes\Bin",
		"BinSearch" => "NetSuite\Classes\BinSearch",
		"BinSearchAdvanced" => "NetSuite\Classes\BinSearchAdvanced",
		"BinSearchRow" => "NetSuite\Classes\BinSearchRow",
		"SalesTaxItem" => "NetSuite\Classes\SalesTaxItem",
		"TaxGroup" => "NetSuite\Classes\TaxGroup",
		"TaxGroupTaxItem" => "NetSuite\Classes\TaxGroupTaxItem",
		"TaxGroupTaxItemList" => "NetSuite\Classes\TaxGroupTaxItemList",
		"TaxType" => "NetSuite\Classes\TaxType",
		"TaxTypeNexusesTax" => "NetSuite\Classes\TaxTypeNexusesTax",
		"TaxTypeNexusesTaxList" => "NetSuite\Classes\TaxTypeNexusesTaxList",
		"SerializedInventoryItem" => "NetSuite\Classes\SerializedInventoryItem",
		"SerializedInventoryItemLocations" => "NetSuite\Classes\SerializedInventoryItemLocations",
		"SerializedInventoryItemLocationsList" => "NetSuite\Classes\SerializedInventoryItemLocationsList",
		"SerializedInventoryItemNumbers" => "NetSuite\Classes\SerializedInventoryItemNumbers",
		"SerializedInventoryItemNumbersList" => "NetSuite\Classes\SerializedInventoryItemNumbersList",
		"LotNumberedInventoryItem" => "NetSuite\Classes\LotNumberedInventoryItem",
		"LotNumberedInventoryItemLocations" => "NetSuite\Classes\LotNumberedInventoryItemLocations",
		"LotNumberedInventoryItemLocationsList" => "NetSuite\Classes\LotNumberedInventoryItemLocationsList",
		"LotNumberedInventoryItemNumbers" => "NetSuite\Classes\LotNumberedInventoryItemNumbers",
		"LotNumberedInventoryItemNumbersList" => "NetSuite\Classes\LotNumberedInventoryItemNumbersList",
		"GiftCertificateItem" => "NetSuite\Classes\GiftCertificateItem",
		"GiftCertificateItemAuthCodes" => "NetSuite\Classes\GiftCertificateItemAuthCodes",
		"GiftCertificateItemAuthCodesList" => "NetSuite\Classes\GiftCertificateItemAuthCodesList",
		"Subsidiary" => "NetSuite\Classes\Subsidiary",
		"SubsidiaryNexus" => "NetSuite\Classes\SubsidiaryNexus",
		"SubsidiaryNexusList" => "NetSuite\Classes\SubsidiaryNexusList",
		"SubsidiarySearch" => "NetSuite\Classes\SubsidiarySearch",
		"SubsidiarySearchAdvanced" => "NetSuite\Classes\SubsidiarySearchAdvanced",
		"SubsidiarySearchRow" => "NetSuite\Classes\SubsidiarySearchRow",
		"GiftCertificate" => "NetSuite\Classes\GiftCertificate",
		"GiftCertificateSearch" => "NetSuite\Classes\GiftCertificateSearch",
		"GiftCertificateSearchAdvanced" => "NetSuite\Classes\GiftCertificateSearchAdvanced",
		"GiftCertificateSearchRow" => "NetSuite\Classes\GiftCertificateSearchRow",
		"PartnerCategory" => "NetSuite\Classes\PartnerCategory",
		"VendorCategory" => "NetSuite\Classes\VendorCategory",
		"KitItem" => "NetSuite\Classes\KitItem",
		"AssemblyItem" => "NetSuite\Classes\AssemblyItem",
		"SerializedAssemblyItem" => "NetSuite\Classes\SerializedAssemblyItem",
		"LotNumberedAssemblyItem" => "NetSuite\Classes\LotNumberedAssemblyItem",
		"ServiceItemTaskTemplates" => "NetSuite\Classes\ServiceItemTaskTemplates",
		"ServiceItemTaskTemplatesList" => "NetSuite\Classes\ServiceItemTaskTemplatesList",
		"State" => "NetSuite\Classes\State",
		"AccountingPeriod" => "NetSuite\Classes\AccountingPeriod",
		"BudgetCategory" => "NetSuite\Classes\BudgetCategory",
		"AccountingPeriodSearch" => "NetSuite\Classes\AccountingPeriodSearch",
		"AccountingPeriodSearchAdvanced" => "NetSuite\Classes\AccountingPeriodSearchAdvanced",
		"AccountingPeriodSearchRow" => "NetSuite\Classes\AccountingPeriodSearchRow",
		"ContactCategorySearch" => "NetSuite\Classes\ContactCategorySearch",
		"ContactCategorySearchAdvanced" => "NetSuite\Classes\ContactCategorySearchAdvanced",
		"ContactCategorySearchRow" => "NetSuite\Classes\ContactCategorySearchRow",
		"ContactRoleSearch" => "NetSuite\Classes\ContactRoleSearch",
		"ContactRoleSearchAdvanced" => "NetSuite\Classes\ContactRoleSearchAdvanced",
		"ContactRoleSearchRow" => "NetSuite\Classes\ContactRoleSearchRow",
		"CustomerCategorySearch" => "NetSuite\Classes\CustomerCategorySearch",
		"CustomerCategorySearchAdvanced" => "NetSuite\Classes\CustomerCategorySearchAdvanced",
		"CustomerCategorySearchRow" => "NetSuite\Classes\CustomerCategorySearchRow",
		"ExpenseCategorySearch" => "NetSuite\Classes\ExpenseCategorySearch",
		"ExpenseCategorySearchAdvanced" => "NetSuite\Classes\ExpenseCategorySearchAdvanced",
		"ExpenseCategorySearchRow" => "NetSuite\Classes\ExpenseCategorySearchRow",
		"NoteTypeSearch" => "NetSuite\Classes\NoteTypeSearch",
		"NoteTypeSearchAdvanced" => "NetSuite\Classes\NoteTypeSearchAdvanced",
		"NoteTypeSearchRow" => "NetSuite\Classes\NoteTypeSearchRow",
		"PartnerCategorySearch" => "NetSuite\Classes\PartnerCategorySearch",
		"PartnerCategorySearchAdvanced" => "NetSuite\Classes\PartnerCategorySearchAdvanced",
		"PartnerCategorySearchRow" => "NetSuite\Classes\PartnerCategorySearchRow",
		"PaymentMethodSearch" => "NetSuite\Classes\PaymentMethodSearch",
		"PaymentMethodSearchAdvanced" => "NetSuite\Classes\PaymentMethodSearchAdvanced",
		"PaymentMethodSearchRow" => "NetSuite\Classes\PaymentMethodSearchRow",
		"PriceLevelSearch" => "NetSuite\Classes\PriceLevelSearch",
		"PriceLevelSearchAdvanced" => "NetSuite\Classes\PriceLevelSearchAdvanced",
		"PriceLevelSearchRow" => "NetSuite\Classes\PriceLevelSearchRow",
		"SalesRoleSearch" => "NetSuite\Classes\SalesRoleSearch",
		"SalesRoleSearchAdvanced" => "NetSuite\Classes\SalesRoleSearchAdvanced",
		"SalesRoleSearchRow" => "NetSuite\Classes\SalesRoleSearchRow",
		"TermSearch" => "NetSuite\Classes\TermSearch",
		"TermSearchAdvanced" => "NetSuite\Classes\TermSearchAdvanced",
		"TermSearchRow" => "NetSuite\Classes\TermSearchRow",
		"VendorCategorySearch" => "NetSuite\Classes\VendorCategorySearch",
		"VendorCategorySearchAdvanced" => "NetSuite\Classes\VendorCategorySearchAdvanced",
		"VendorCategorySearchRow" => "NetSuite\Classes\VendorCategorySearchRow",
		"WinLossReasonSearch" => "NetSuite\Classes\WinLossReasonSearch",
		"WinLossReasonSearchAdvanced" => "NetSuite\Classes\WinLossReasonSearchAdvanced",
		"WinLossReasonSearchRow" => "NetSuite\Classes\WinLossReasonSearchRow",
		"UnitsTypeSearch" => "NetSuite\Classes\UnitsTypeSearch",
		"UnitsTypeSearchAdvanced" => "NetSuite\Classes\UnitsTypeSearchAdvanced",
		"UnitsTypeSearchRow" => "NetSuite\Classes\UnitsTypeSearchRow",
		"PricingGroup" => "NetSuite\Classes\PricingGroup",
		"PricingGroupSearch" => "NetSuite\Classes\PricingGroupSearch",
		"PricingGroupSearchAdvanced" => "NetSuite\Classes\PricingGroupSearchAdvanced",
		"PricingGroupSearchRow" => "NetSuite\Classes\PricingGroupSearchRow",
		"InventoryNumber" => "NetSuite\Classes\InventoryNumber",
		"InventoryNumberLocations" => "NetSuite\Classes\InventoryNumberLocations",
		"InventoryNumberLocationsList" => "NetSuite\Classes\InventoryNumberLocationsList",
		"InventoryNumberSearch" => "NetSuite\Classes\InventoryNumberSearch",
		"InventoryNumberSearchAdvanced" => "NetSuite\Classes\InventoryNumberSearchAdvanced",
		"InventoryNumberSearchRow" => "NetSuite\Classes\InventoryNumberSearchRow",
		"RevRecSchedule" => "NetSuite\Classes\RevRecSchedule",
		"RevRecScheduleRecurrence" => "NetSuite\Classes\RevRecScheduleRecurrence",
		"RevRecScheduleRecurrenceList" => "NetSuite\Classes\RevRecScheduleRecurrenceList",
		"RevRecTemplate" => "NetSuite\Classes\RevRecTemplate",
		"RevRecTemplateRecurrence" => "NetSuite\Classes\RevRecTemplateRecurrence",
		"RevRecTemplateRecurrenceList" => "NetSuite\Classes\RevRecTemplateRecurrenceList",
		"RevRecScheduleSearch" => "NetSuite\Classes\RevRecScheduleSearch",
		"RevRecScheduleSearchAdvanced" => "NetSuite\Classes\RevRecScheduleSearchAdvanced",
		"RevRecScheduleSearchRow" => "NetSuite\Classes\RevRecScheduleSearchRow",
		"RevRecTemplateSearch" => "NetSuite\Classes\RevRecTemplateSearch",
		"RevRecTemplateSearchAdvanced" => "NetSuite\Classes\RevRecTemplateSearchAdvanced",
		"RevRecTemplateSearchRow" => "NetSuite\Classes\RevRecTemplateSearchRow",
		"CostCategory" => "NetSuite\Classes\CostCategory",
		"Nexus" => "NetSuite\Classes\Nexus",
		"NexusSearch" => "NetSuite\Classes\NexusSearch",
		"NexusSearchAdvanced" => "NetSuite\Classes\NexusSearchAdvanced",
		"NexusSearchRow" => "NetSuite\Classes\NexusSearchRow",
		"CustomerMessage" => "NetSuite\Classes\CustomerMessage",
		"OtherNameCategory" => "NetSuite\Classes\OtherNameCategory",
		"OtherNameCategorySearch" => "NetSuite\Classes\OtherNameCategorySearch",
		"OtherNameCategorySearchAdvanced" => "NetSuite\Classes\OtherNameCategorySearchAdvanced",
		"OtherNameCategorySearchRow" => "NetSuite\Classes\OtherNameCategorySearchRow",
		"CustomerMessageSearch" => "NetSuite\Classes\CustomerMessageSearch",
		"CustomerMessageSearchAdvanced" => "NetSuite\Classes\CustomerMessageSearchAdvanced",
		"CustomerMessageSearchRow" => "NetSuite\Classes\CustomerMessageSearchRow",
		"ItemGroup" => "NetSuite\Classes\ItemGroup",
		"CurrencyRateSearch" => "NetSuite\Classes\CurrencyRateSearch",
		"CurrencyRateSearchAdvanced" => "NetSuite\Classes\CurrencyRateSearchAdvanced",
		"CurrencyRateSearchRow" => "NetSuite\Classes\CurrencyRateSearchRow",
		"ItemRevision" => "NetSuite\Classes\ItemRevision",
		"ItemRevisionSearch" => "NetSuite\Classes\ItemRevisionSearch",
		"ItemRevisionSearchAdvanced" => "NetSuite\Classes\ItemRevisionSearchAdvanced",
		"ItemRevisionSearchRow" => "NetSuite\Classes\ItemRevisionSearchRow",
		"AccountingPeriodFiscalCalendars" => "NetSuite\Classes\AccountingPeriodFiscalCalendars",
		"AccountingPeriodFiscalCalendarsList" => "NetSuite\Classes\AccountingPeriodFiscalCalendarsList",
		"TaxAcct" => "NetSuite\Classes\TaxAcct",
		"ExpenseCategoryRates" => "NetSuite\Classes\ExpenseCategoryRates",
		"ExpenseCategoryRatesList" => "NetSuite\Classes\ExpenseCategoryRatesList",
		"BillingSchedule" => "NetSuite\Classes\BillingSchedule",
		"BillingScheduleMilestone" => "NetSuite\Classes\BillingScheduleMilestone",
		"BillingScheduleMilestoneList" => "NetSuite\Classes\BillingScheduleMilestoneList",
		"BillingScheduleRecurrence" => "NetSuite\Classes\BillingScheduleRecurrence",
		"BillingScheduleRecurrenceList" => "NetSuite\Classes\BillingScheduleRecurrenceList",
		"BillingScheduleSearch" => "NetSuite\Classes\BillingScheduleSearch",
		"BillingScheduleSearchAdvanced" => "NetSuite\Classes\BillingScheduleSearchAdvanced",
		"BillingScheduleSearchRow" => "NetSuite\Classes\BillingScheduleSearchRow",
		"GlobalAccountMapping" => "NetSuite\Classes\GlobalAccountMapping",
		"GlobalAccountMappingSearch" => "NetSuite\Classes\GlobalAccountMappingSearch",
		"GlobalAccountMappingSearchAdvanced" => "NetSuite\Classes\GlobalAccountMappingSearchAdvanced",
		"GlobalAccountMappingSearchRow" => "NetSuite\Classes\GlobalAccountMappingSearchRow",
		"ItemAccountMapping" => "NetSuite\Classes\ItemAccountMapping",
		"ItemAccountMappingSearch" => "NetSuite\Classes\ItemAccountMappingSearch",
		"ItemAccountMappingSearchAdvanced" => "NetSuite\Classes\ItemAccountMappingSearchAdvanced",
		"ItemAccountMappingSearchRow" => "NetSuite\Classes\ItemAccountMappingSearchRow",
		"ItemAccountingBookDetail" => "NetSuite\Classes\ItemAccountingBookDetail",
		"ItemAccountingBookDetailList" => "NetSuite\Classes\ItemAccountingBookDetailList",
		"SubsidiaryAccountingBookDetail" => "NetSuite\Classes\SubsidiaryAccountingBookDetail",
		"SubsidiaryAccountingBookDetailList" => "NetSuite\Classes\SubsidiaryAccountingBookDetailList",
		"PaymentMethodVisuals" => "NetSuite\Classes\PaymentMethodVisuals",
		"PaymentMethodVisualsList" => "NetSuite\Classes\PaymentMethodVisualsList",
		"FairValuePrice" => "NetSuite\Classes\FairValuePrice",
		"FairValuePriceSearch" => "NetSuite\Classes\FairValuePriceSearch",
		"FairValuePriceSearchAdvanced" => "NetSuite\Classes\FairValuePriceSearchAdvanced",
		"FairValuePriceSearchRow" => "NetSuite\Classes\FairValuePriceSearchRow",
		"LocationRegions" => "NetSuite\Classes\LocationRegions",
		"LocationRegionsList" => "NetSuite\Classes\LocationRegionsList",
		"TaxTypeNexusAccounts" => "NetSuite\Classes\TaxTypeNexusAccounts",
		"TaxTypeNexusAccountsList" => "NetSuite\Classes\TaxTypeNexusAccountsList",
		"SubsidiaryTaxRegistration" => "NetSuite\Classes\SubsidiaryTaxRegistration",
		"SubsidiaryTaxRegistrationList" => "NetSuite\Classes\SubsidiaryTaxRegistrationList",
		"CostCategorySearch" => "NetSuite\Classes\CostCategorySearch",
		"CostCategorySearchAdvanced" => "NetSuite\Classes\CostCategorySearchAdvanced",
		"CostCategorySearchRow" => "NetSuite\Classes\CostCategorySearchRow",
		"AccountLocalizations" => "NetSuite\Classes\AccountLocalizations",
		"AccountLocalizationsList" => "NetSuite\Classes\AccountLocalizationsList",
		"ConsolidatedExchangeRate" => "NetSuite\Classes\ConsolidatedExchangeRate",
		"ConsolidatedExchangeRateSearch" => "NetSuite\Classes\ConsolidatedExchangeRateSearch",
		"ConsolidatedExchangeRateSearchAdvanced" => "NetSuite\Classes\ConsolidatedExchangeRateSearchAdvanced",
		"ConsolidatedExchangeRateSearchRow" => "NetSuite\Classes\ConsolidatedExchangeRateSearchRow",
		"TaxGroupSearch" => "NetSuite\Classes\TaxGroupSearch",
		"TaxGroupSearchAdvanced" => "NetSuite\Classes\TaxGroupSearchAdvanced",
		"TaxGroupSearchRow" => "NetSuite\Classes\TaxGroupSearchRow",
		"SalesTaxItemSearch" => "NetSuite\Classes\SalesTaxItemSearch",
		"SalesTaxItemSearchAdvanced" => "NetSuite\Classes\SalesTaxItemSearchAdvanced",
		"SalesTaxItemSearchRow" => "NetSuite\Classes\SalesTaxItemSearchRow",
		"TaxTypeSearch" => "NetSuite\Classes\TaxTypeSearch",
		"TaxTypeSearchAdvanced" => "NetSuite\Classes\TaxTypeSearchAdvanced",
		"TaxTypeSearchRow" => "NetSuite\Classes\TaxTypeSearchRow",
		"LocationBusinessHours" => "NetSuite\Classes\LocationBusinessHours",
		"LocationBusinessHoursList" => "NetSuite\Classes\LocationBusinessHoursList",
		"SalesOrderItemCommitInventory" => "NetSuite\Classes\SalesOrderItemCommitInventory",
		"SalesOrderItemCreatePo" => "NetSuite\Classes\SalesOrderItemCreatePo",
		"SalesOrderOrderStatus" => "NetSuite\Classes\SalesOrderOrderStatus",
		"ItemFulfillmentExportTypeUps" => "NetSuite\Classes\ItemFulfillmentExportTypeUps",
		"ItemFulfillmentLicenseExceptionUps" => "NetSuite\Classes\ItemFulfillmentLicenseExceptionUps",
		"ItemFulfillmentMethodOfTransportUps" => "NetSuite\Classes\ItemFulfillmentMethodOfTransportUps",
		"ItemFulfillmentThirdPartyTypeUps" => "NetSuite\Classes\ItemFulfillmentThirdPartyTypeUps",
		"ItemFulfillmentPackageUpsCodMethodUps" => "NetSuite\Classes\ItemFulfillmentPackageUpsCodMethodUps",
		"ItemFulfillmentPackageUpsDeliveryConfUps" => "NetSuite\Classes\ItemFulfillmentPackageUpsDeliveryConfUps",
		"ItemFulfillmentPackageUpsPackagingUps" => "NetSuite\Classes\ItemFulfillmentPackageUpsPackagingUps",
		"ItemFulfillmentPackageUspsDeliveryConfUsps" => "NetSuite\Classes\ItemFulfillmentPackageUspsDeliveryConfUsps",
		"ItemFulfillmentPackageUspsPackagingUsps" => "NetSuite\Classes\ItemFulfillmentPackageUspsPackagingUsps",
		"ItemFulfillmentB13AFilingOptionFedEx" => "NetSuite\Classes\ItemFulfillmentB13AFilingOptionFedEx",
		"ItemFulfillmentHomeDeliveryTypeFedEx" => "NetSuite\Classes\ItemFulfillmentHomeDeliveryTypeFedEx",
		"ItemFulfillmentThirdPartyTypeFedEx" => "NetSuite\Classes\ItemFulfillmentThirdPartyTypeFedEx",
		"ItemFulfillmentPackageFedExAdmPackageTypeFedEx" => "NetSuite\Classes\ItemFulfillmentPackageFedExAdmPackageTypeFedEx",
		"ItemFulfillmentPackageFedExCodMethodFedEx" => "NetSuite\Classes\ItemFulfillmentPackageFedExCodMethodFedEx",
		"ItemFulfillmentPackageFedExDeliveryConfFedEx" => "NetSuite\Classes\ItemFulfillmentPackageFedExDeliveryConfFedEx",
		"ItemFulfillmentPackageFedExPackagingFedEx" => "NetSuite\Classes\ItemFulfillmentPackageFedExPackagingFedEx",
		"ItemFulfillmentPackageFedExSignatureOptionsFedEx" => "NetSuite\Classes\ItemFulfillmentPackageFedExSignatureOptionsFedEx",
		"ItemFulfillmentTermsOfSaleFedEx" => "NetSuite\Classes\ItemFulfillmentTermsOfSaleFedEx",
		"ItemFulfillmentShipStatus" => "NetSuite\Classes\ItemFulfillmentShipStatus",
		"OpportunityStatus" => "NetSuite\Classes\OpportunityStatus",
		"TransactionType" => "NetSuite\Classes\TransactionType",
		"TransactionStatus" => "NetSuite\Classes\TransactionStatus",
		"TransactionPaymentEventResult" => "NetSuite\Classes\TransactionPaymentEventResult",
		"TransactionPaymentEventType" => "NetSuite\Classes\TransactionPaymentEventType",
		"TransactionPaymentEventHoldReason" => "NetSuite\Classes\TransactionPaymentEventHoldReason",
		"ItemFulfillmentPackageFedExCodFreightTypeFedEx" => "NetSuite\Classes\ItemFulfillmentPackageFedExCodFreightTypeFedEx",
		"TransactionLinkType" => "NetSuite\Classes\TransactionLinkType",
		"ForecastType" => "NetSuite\Classes\ForecastType",
		"TransactionLineType" => "NetSuite\Classes\TransactionLineType",
		"TransactionApprovalStatus" => "NetSuite\Classes\TransactionApprovalStatus",
		"ItemFulfillmentPackageFedExPriorityAlertTypeFedEx" => "NetSuite\Classes\ItemFulfillmentPackageFedExPriorityAlertTypeFedEx",
		"ItemFulfillmentHazmatTypeFedEx" => "NetSuite\Classes\ItemFulfillmentHazmatTypeFedEx",
		"ItemFulfillmentAncillaryEndorsementFedEx" => "NetSuite\Classes\ItemFulfillmentAncillaryEndorsementFedEx",
		"ItemFulfillmentAccessibilityTypeFedEx" => "NetSuite\Classes\ItemFulfillmentAccessibilityTypeFedEx",
		"TransactionChargeType" => "NetSuite\Classes\TransactionChargeType",
		"AccountingTransactionRevCommitStatus" => "NetSuite\Classes\AccountingTransactionRevCommitStatus",
		"AccountingTransactionRevenueStatus" => "NetSuite\Classes\AccountingTransactionRevenueStatus",
		"SalesOrderItemFulfillmentChoice" => "NetSuite\Classes\SalesOrderItemFulfillmentChoice",
		"Opportunity" => "NetSuite\Classes\Opportunity",
		"OpportunitySalesTeam" => "NetSuite\Classes\OpportunitySalesTeam",
		"OpportunitySalesTeamList" => "NetSuite\Classes\OpportunitySalesTeamList",
		"OpportunityItem" => "NetSuite\Classes\OpportunityItem",
		"OpportunityItemList" => "NetSuite\Classes\OpportunityItemList",
		"OpportunityCompetitors" => "NetSuite\Classes\OpportunityCompetitors",
		"OpportunityCompetitorsList" => "NetSuite\Classes\OpportunityCompetitorsList",
		"OpportunitySearch" => "NetSuite\Classes\OpportunitySearch",
		"OpportunitySearchAdvanced" => "NetSuite\Classes\OpportunitySearchAdvanced",
		"OpportunitySearchRow" => "NetSuite\Classes\OpportunitySearchRow",
		"OpportunityPartnersList" => "NetSuite\Classes\OpportunityPartnersList",
		"SalesOrder" => "NetSuite\Classes\SalesOrder",
		"SalesOrderSalesTeam" => "NetSuite\Classes\SalesOrderSalesTeam",
		"SalesOrderSalesTeamList" => "NetSuite\Classes\SalesOrderSalesTeamList",
		"SalesOrderItem" => "NetSuite\Classes\SalesOrderItem",
		"SalesOrderItemList" => "NetSuite\Classes\SalesOrderItemList",
		"SalesOrderPartnersList" => "NetSuite\Classes\SalesOrderPartnersList",
		"SalesOrderShipGroupList" => "NetSuite\Classes\SalesOrderShipGroupList",
		"TransactionSearch" => "NetSuite\Classes\TransactionSearch",
		"TransactionSearchAdvanced" => "NetSuite\Classes\TransactionSearchAdvanced",
		"TransactionSearchRow" => "NetSuite\Classes\TransactionSearchRow",
		"ItemFulfillment" => "NetSuite\Classes\ItemFulfillment",
		"ItemFulfillmentItem" => "NetSuite\Classes\ItemFulfillmentItem",
		"ItemFulfillmentItemList" => "NetSuite\Classes\ItemFulfillmentItemList",
		"ItemFulfillmentPackage" => "NetSuite\Classes\ItemFulfillmentPackage",
		"ItemFulfillmentPackageList" => "NetSuite\Classes\ItemFulfillmentPackageList",
		"ItemFulfillmentPackageUps" => "NetSuite\Classes\ItemFulfillmentPackageUps",
		"ItemFulfillmentPackageUpsList" => "NetSuite\Classes\ItemFulfillmentPackageUpsList",
		"ItemFulfillmentPackageUsps" => "NetSuite\Classes\ItemFulfillmentPackageUsps",
		"ItemFulfillmentPackageUspsList" => "NetSuite\Classes\ItemFulfillmentPackageUspsList",
		"ItemFulfillmentPackageFedEx" => "NetSuite\Classes\ItemFulfillmentPackageFedEx",
		"ItemFulfillmentPackageFedExList" => "NetSuite\Classes\ItemFulfillmentPackageFedExList",
		"Invoice" => "NetSuite\Classes\Invoice",
		"InvoiceSalesTeam" => "NetSuite\Classes\InvoiceSalesTeam",
		"InvoiceSalesTeamList" => "NetSuite\Classes\InvoiceSalesTeamList",
		"InvoiceItem" => "NetSuite\Classes\InvoiceItem",
		"InvoiceItemList" => "NetSuite\Classes\InvoiceItemList",
		"InvoiceItemCost" => "NetSuite\Classes\InvoiceItemCost",
		"InvoiceItemCostList" => "NetSuite\Classes\InvoiceItemCostList",
		"InvoiceExpCost" => "NetSuite\Classes\InvoiceExpCost",
		"InvoiceExpCostList" => "NetSuite\Classes\InvoiceExpCostList",
		"InvoiceTime" => "NetSuite\Classes\InvoiceTime",
		"InvoiceTimeList" => "NetSuite\Classes\InvoiceTimeList",
		"InvoicePartnersList" => "NetSuite\Classes\InvoicePartnersList",
		"InvoiceShipGroupList" => "NetSuite\Classes\InvoiceShipGroupList",
		"CashSale" => "NetSuite\Classes\CashSale",
		"CashSaleSalesTeam" => "NetSuite\Classes\CashSaleSalesTeam",
		"CashSaleSalesTeamList" => "NetSuite\Classes\CashSaleSalesTeamList",
		"CashSaleItem" => "NetSuite\Classes\CashSaleItem",
		"CashSaleItemList" => "NetSuite\Classes\CashSaleItemList",
		"CashSaleItemCost" => "NetSuite\Classes\CashSaleItemCost",
		"CashSaleItemCostList" => "NetSuite\Classes\CashSaleItemCostList",
		"CashSaleExpCost" => "NetSuite\Classes\CashSaleExpCost",
		"CashSaleExpCostList" => "NetSuite\Classes\CashSaleExpCostList",
		"CashSaleTime" => "NetSuite\Classes\CashSaleTime",
		"CashSaleTimeList" => "NetSuite\Classes\CashSaleTimeList",
		"CashSalePartnersList" => "NetSuite\Classes\CashSalePartnersList",
		"CashSaleShipGroupList" => "NetSuite\Classes\CashSaleShipGroupList",
		"Estimate" => "NetSuite\Classes\Estimate",
		"EstimateItem" => "NetSuite\Classes\EstimateItem",
		"EstimateItemList" => "NetSuite\Classes\EstimateItemList",
		"EstimateSalesTeam" => "NetSuite\Classes\EstimateSalesTeam",
		"EstimateSalesTeamList" => "NetSuite\Classes\EstimateSalesTeamList",
		"EstimatePartnersList" => "NetSuite\Classes\EstimatePartnersList",
		"EstimateShipGroupList" => "NetSuite\Classes\EstimateShipGroupList",
		"GiftCertRedemption" => "NetSuite\Classes\GiftCertRedemption",
		"GiftCertRedemptionList" => "NetSuite\Classes\GiftCertRedemptionList",
		"TransactionShipGroup" => "NetSuite\Classes\TransactionShipGroup",
		"AccountingTransactionSearch" => "NetSuite\Classes\AccountingTransactionSearch",
		"AccountingTransactionSearchAdvanced" => "NetSuite\Classes\AccountingTransactionSearchAdvanced",
		"AccountingTransactionSearchRow" => "NetSuite\Classes\AccountingTransactionSearchRow",
		"Promotions" => "NetSuite\Classes\Promotions",
		"PromotionsList" => "NetSuite\Classes\PromotionsList",
		"Usage" => "NetSuite\Classes\Usage",
		"UsageSearch" => "NetSuite\Classes\UsageSearch",
		"UsageSearchAdvanced" => "NetSuite\Classes\UsageSearchAdvanced",
		"UsageSearchRow" => "NetSuite\Classes\UsageSearchRow",
		"PurchaseOrderOrderStatus" => "NetSuite\Classes\PurchaseOrderOrderStatus",
		"TransactionBillVarianceStatus" => "NetSuite\Classes\TransactionBillVarianceStatus",
		"VendorReturnAuthorizationOrderStatus" => "NetSuite\Classes\VendorReturnAuthorizationOrderStatus",
		"PurchLandedCostList" => "NetSuite\Classes\PurchLandedCostList",
		"VendorBill" => "NetSuite\Classes\VendorBill",
		"VendorBillExpense" => "NetSuite\Classes\VendorBillExpense",
		"VendorBillExpenseList" => "NetSuite\Classes\VendorBillExpenseList",
		"VendorBillItem" => "NetSuite\Classes\VendorBillItem",
		"VendorBillItemList" => "NetSuite\Classes\VendorBillItemList",
		"PurchaseOrder" => "NetSuite\Classes\PurchaseOrder",
		"PurchaseOrderExpense" => "NetSuite\Classes\PurchaseOrderExpense",
		"PurchaseOrderExpenseList" => "NetSuite\Classes\PurchaseOrderExpenseList",
		"PurchaseOrderItem" => "NetSuite\Classes\PurchaseOrderItem",
		"PurchaseOrderItemList" => "NetSuite\Classes\PurchaseOrderItemList",
		"ItemReceipt" => "NetSuite\Classes\ItemReceipt",
		"ItemReceiptItem" => "NetSuite\Classes\ItemReceiptItem",
		"ItemReceiptItemList" => "NetSuite\Classes\ItemReceiptItemList",
		"ItemReceiptExpense" => "NetSuite\Classes\ItemReceiptExpense",
		"ItemReceiptExpenseList" => "NetSuite\Classes\ItemReceiptExpenseList",
		"VendorPayment" => "NetSuite\Classes\VendorPayment",
		"VendorPaymentApply" => "NetSuite\Classes\VendorPaymentApply",
		"VendorPaymentApplyList" => "NetSuite\Classes\VendorPaymentApplyList",
		"VendorPaymentCredit" => "NetSuite\Classes\VendorPaymentCredit",
		"VendorPaymentCreditList" => "NetSuite\Classes\VendorPaymentCreditList",
		"VendorCredit" => "NetSuite\Classes\VendorCredit",
		"VendorCreditExpense" => "NetSuite\Classes\VendorCreditExpense",
		"VendorCreditExpenseList" => "NetSuite\Classes\VendorCreditExpenseList",
		"VendorCreditItem" => "NetSuite\Classes\VendorCreditItem",
		"VendorCreditItemList" => "NetSuite\Classes\VendorCreditItemList",
		"VendorCreditApply" => "NetSuite\Classes\VendorCreditApply",
		"VendorCreditApplyList" => "NetSuite\Classes\VendorCreditApplyList",
		"VendorReturnAuthorization" => "NetSuite\Classes\VendorReturnAuthorization",
		"VendorReturnAuthorizationExpense" => "NetSuite\Classes\VendorReturnAuthorizationExpense",
		"VendorReturnAuthorizationExpenseList" => "NetSuite\Classes\VendorReturnAuthorizationExpenseList",
		"VendorReturnAuthorizationItem" => "NetSuite\Classes\VendorReturnAuthorizationItem",
		"VendorReturnAuthorizationItemList" => "NetSuite\Classes\VendorReturnAuthorizationItemList",
		"PurchaseRequisition" => "NetSuite\Classes\PurchaseRequisition",
		"PurchaseRequisitionExpense" => "NetSuite\Classes\PurchaseRequisitionExpense",
		"PurchaseRequisitionExpenseList" => "NetSuite\Classes\PurchaseRequisitionExpenseList",
		"PurchaseRequisitionItem" => "NetSuite\Classes\PurchaseRequisitionItem",
		"PurchaseRequisitionItemList" => "NetSuite\Classes\PurchaseRequisitionItemList",
		"ReturnAuthorizationOrderStatus" => "NetSuite\Classes\ReturnAuthorizationOrderStatus",
		"ChargeStage" => "NetSuite\Classes\ChargeStage",
		"ChargeUse" => "NetSuite\Classes\ChargeUse",
		"CashRefund" => "NetSuite\Classes\CashRefund",
		"CashRefundItem" => "NetSuite\Classes\CashRefundItem",
		"CashRefundItemList" => "NetSuite\Classes\CashRefundItemList",
		"CashRefundSalesTeam" => "NetSuite\Classes\CashRefundSalesTeam",
		"CashRefundSalesTeamList" => "NetSuite\Classes\CashRefundSalesTeamList",
		"CashRefundPartnersList" => "NetSuite\Classes\CashRefundPartnersList",
		"CustomerPayment" => "NetSuite\Classes\CustomerPayment",
		"CustomerPaymentApply" => "NetSuite\Classes\CustomerPaymentApply",
		"CustomerPaymentApplyList" => "NetSuite\Classes\CustomerPaymentApplyList",
		"CustomerPaymentCredit" => "NetSuite\Classes\CustomerPaymentCredit",
		"CustomerPaymentCreditList" => "NetSuite\Classes\CustomerPaymentCreditList",
		"CustomerPaymentDeposit" => "NetSuite\Classes\CustomerPaymentDeposit",
		"CustomerPaymentDepositList" => "NetSuite\Classes\CustomerPaymentDepositList",
		"ReturnAuthorization" => "NetSuite\Classes\ReturnAuthorization",
		"ReturnAuthorizationItem" => "NetSuite\Classes\ReturnAuthorizationItem",
		"ReturnAuthorizationItemList" => "NetSuite\Classes\ReturnAuthorizationItemList",
		"ReturnAuthorizationSalesTeam" => "NetSuite\Classes\ReturnAuthorizationSalesTeam",
		"ReturnAuthorizationSalesTeamList" => "NetSuite\Classes\ReturnAuthorizationSalesTeamList",
		"ReturnAuthorizationPartnersList" => "NetSuite\Classes\ReturnAuthorizationPartnersList",
		"CreditMemo" => "NetSuite\Classes\CreditMemo",
		"CreditMemoSalesTeam" => "NetSuite\Classes\CreditMemoSalesTeam",
		"CreditMemoSalesTeamList" => "NetSuite\Classes\CreditMemoSalesTeamList",
		"CreditMemoItem" => "NetSuite\Classes\CreditMemoItem",
		"CreditMemoItemList" => "NetSuite\Classes\CreditMemoItemList",
		"CreditMemoApply" => "NetSuite\Classes\CreditMemoApply",
		"CreditMemoApplyList" => "NetSuite\Classes\CreditMemoApplyList",
		"CreditMemoPartnersList" => "NetSuite\Classes\CreditMemoPartnersList",
		"CustomerRefund" => "NetSuite\Classes\CustomerRefund",
		"CustomerRefundApply" => "NetSuite\Classes\CustomerRefundApply",
		"CustomerRefundApplyList" => "NetSuite\Classes\CustomerRefundApplyList",
		"CustomerRefundDeposit" => "NetSuite\Classes\CustomerRefundDeposit",
		"CustomerRefundDepositList" => "NetSuite\Classes\CustomerRefundDepositList",
		"CustomerDeposit" => "NetSuite\Classes\CustomerDeposit",
		"CustomerDepositApply" => "NetSuite\Classes\CustomerDepositApply",
		"CustomerDepositApplyList" => "NetSuite\Classes\CustomerDepositApplyList",
		"DepositApplication" => "NetSuite\Classes\DepositApplication",
		"DepositApplicationApply" => "NetSuite\Classes\DepositApplicationApply",
		"DepositApplicationApplyList" => "NetSuite\Classes\DepositApplicationApplyList",
		"Charge" => "NetSuite\Classes\Charge",
		"ChargeSearch" => "NetSuite\Classes\ChargeSearch",
		"ChargeSearchAdvanced" => "NetSuite\Classes\ChargeSearchAdvanced",
		"ChargeSearchRow" => "NetSuite\Classes\ChargeSearchRow",
		"BudgetBudgetType" => "NetSuite\Classes\BudgetBudgetType",
		"Budget" => "NetSuite\Classes\Budget",
		"BudgetSearch" => "NetSuite\Classes\BudgetSearch",
		"BudgetSearchAdvanced" => "NetSuite\Classes\BudgetSearchAdvanced",
		"BudgetSearchRow" => "NetSuite\Classes\BudgetSearchRow",
		"CheckLandedCostList" => "NetSuite\Classes\CheckLandedCostList",
		"Check" => "NetSuite\Classes\Check",
		"CheckExpense" => "NetSuite\Classes\CheckExpense",
		"CheckExpenseList" => "NetSuite\Classes\CheckExpenseList",
		"CheckItem" => "NetSuite\Classes\CheckItem",
		"CheckItemList" => "NetSuite\Classes\CheckItemList",
		"Deposit" => "NetSuite\Classes\Deposit",
		"DepositPayment" => "NetSuite\Classes\DepositPayment",
		"DepositPaymentList" => "NetSuite\Classes\DepositPaymentList",
		"DepositCashBack" => "NetSuite\Classes\DepositCashBack",
		"DepositCashBackList" => "NetSuite\Classes\DepositCashBackList",
		"DepositOther" => "NetSuite\Classes\DepositOther",
		"DepositOtherList" => "NetSuite\Classes\DepositOtherList",
		"TransferOrderItemCommitInventory" => "NetSuite\Classes\TransferOrderItemCommitInventory",
		"TransferOrderOrderStatus" => "NetSuite\Classes\TransferOrderOrderStatus",
		"WorkOrderItemItemCommitInventory" => "NetSuite\Classes\WorkOrderItemItemCommitInventory",
		"WorkOrderOrderStatus" => "NetSuite\Classes\WorkOrderOrderStatus",
		"WorkOrderSchedulingMethod" => "NetSuite\Classes\WorkOrderSchedulingMethod",
		"InventoryAdjustment" => "NetSuite\Classes\InventoryAdjustment",
		"InventoryAdjustmentInventory" => "NetSuite\Classes\InventoryAdjustmentInventory",
		"InventoryAdjustmentInventoryList" => "NetSuite\Classes\InventoryAdjustmentInventoryList",
		"AssemblyBuild" => "NetSuite\Classes\AssemblyBuild",
		"AssemblyUnbuild" => "NetSuite\Classes\AssemblyUnbuild",
		"AssemblyComponent" => "NetSuite\Classes\AssemblyComponent",
		"AssemblyComponentList" => "NetSuite\Classes\AssemblyComponentList",
		"TransferOrder" => "NetSuite\Classes\TransferOrder",
		"TransferOrderItem" => "NetSuite\Classes\TransferOrderItem",
		"TransferOrderItemList" => "NetSuite\Classes\TransferOrderItemList",
		"InterCompanyTransferOrder" => "NetSuite\Classes\InterCompanyTransferOrder",
		"InterCompanyTransferOrderItem" => "NetSuite\Classes\InterCompanyTransferOrderItem",
		"InterCompanyTransferOrderItemList" => "NetSuite\Classes\InterCompanyTransferOrderItemList",
		"WorkOrder" => "NetSuite\Classes\WorkOrder",
		"WorkOrderItem" => "NetSuite\Classes\WorkOrderItem",
		"WorkOrderItemList" => "NetSuite\Classes\WorkOrderItemList",
		"SalesTeamList" => "NetSuite\Classes\SalesTeamList",
		"PartnersList" => "NetSuite\Classes\PartnersList",
		"InventoryTransfer" => "NetSuite\Classes\InventoryTransfer",
		"InventoryTransferInventory" => "NetSuite\Classes\InventoryTransferInventory",
		"InventoryTransferInventoryList" => "NetSuite\Classes\InventoryTransferInventoryList",
		"BinTransfer" => "NetSuite\Classes\BinTransfer",
		"BinTransferInventory" => "NetSuite\Classes\BinTransferInventory",
		"BinTransferInventoryList" => "NetSuite\Classes\BinTransferInventoryList",
		"BinWorksheet" => "NetSuite\Classes\BinWorksheet",
		"BinWorksheetItem" => "NetSuite\Classes\BinWorksheetItem",
		"BinWorksheetItemList" => "NetSuite\Classes\BinWorksheetItemList",
		"WorkOrderIssue" => "NetSuite\Classes\WorkOrderIssue",
		"WorkOrderIssueComponent" => "NetSuite\Classes\WorkOrderIssueComponent",
		"WorkOrderIssueComponentList" => "NetSuite\Classes\WorkOrderIssueComponentList",
		"WorkOrderCompletion" => "NetSuite\Classes\WorkOrderCompletion",
		"WorkOrderCompletionComponent" => "NetSuite\Classes\WorkOrderCompletionComponent",
		"WorkOrderCompletionComponentList" => "NetSuite\Classes\WorkOrderCompletionComponentList",
		"WorkOrderClose" => "NetSuite\Classes\WorkOrderClose",
		"WorkOrderCompletionOperation" => "NetSuite\Classes\WorkOrderCompletionOperation",
		"WorkOrderCompletionOperationList" => "NetSuite\Classes\WorkOrderCompletionOperationList",
		"InventoryCostRevaluation" => "NetSuite\Classes\InventoryCostRevaluation",
		"InventoryCostRevaluationCostComponent" => "NetSuite\Classes\InventoryCostRevaluationCostComponent",
		"InventoryCostRevaluationCostComponentList" => "NetSuite\Classes\InventoryCostRevaluationCostComponentList",
		"JournalEntry" => "NetSuite\Classes\JournalEntry",
		"JournalEntryLine" => "NetSuite\Classes\JournalEntryLine",
		"JournalEntryLineList" => "NetSuite\Classes\JournalEntryLineList",
		"InterCompanyJournalEntry" => "NetSuite\Classes\InterCompanyJournalEntry",
		"InterCompanyJournalEntryLine" => "NetSuite\Classes\InterCompanyJournalEntryLine",
		"InterCompanyJournalEntryLineList" => "NetSuite\Classes\InterCompanyJournalEntryLineList",
		"StatisticalJournalEntry" => "NetSuite\Classes\StatisticalJournalEntry",
		"StatisticalJournalEntryLine" => "NetSuite\Classes\StatisticalJournalEntryLine",
		"StatisticalJournalEntryLineList" => "NetSuite\Classes\StatisticalJournalEntryLineList",
		"InterCompanyJournalEntryAccountingBookDetail" => "NetSuite\Classes\InterCompanyJournalEntryAccountingBookDetail",
		"InterCompanyJournalEntryAccountingBookDetailList" => "NetSuite\Classes\InterCompanyJournalEntryAccountingBookDetailList",
		"CustomizationFieldType" => "NetSuite\Classes\CustomizationFieldType",
		"CustomizationDynamicDefault" => "NetSuite\Classes\CustomizationDynamicDefault",
		"CustomizationDisplayType" => "NetSuite\Classes\CustomizationDisplayType",
		"CustomizationFilterCompareType" => "NetSuite\Classes\CustomizationFilterCompareType",
		"CustomRecordTypePermissionsPermittedLevel" => "NetSuite\Classes\CustomRecordTypePermissionsPermittedLevel",
		"CustomRecordTypePermissionsRestriction" => "NetSuite\Classes\CustomRecordTypePermissionsRestriction",
		"ItemCustomFieldItemSubType" => "NetSuite\Classes\ItemCustomFieldItemSubType",
		"CustomizationAccessLevel" => "NetSuite\Classes\CustomizationAccessLevel",
		"CustomizationSearchLevel" => "NetSuite\Classes\CustomizationSearchLevel",
		"CustomRecordTypeAccessType" => "NetSuite\Classes\CustomRecordTypeAccessType",
		"CustomRecord" => "NetSuite\Classes\CustomRecord",
		"CustomRecordSearch" => "NetSuite\Classes\CustomRecordSearch",
		"CustomRecordSearchAdvanced" => "NetSuite\Classes\CustomRecordSearchAdvanced",
		"CustomRecordSearchRow" => "NetSuite\Classes\CustomRecordSearchRow",
		"CustomList" => "NetSuite\Classes\CustomList",
		"CustomListCustomValue" => "NetSuite\Classes\CustomListCustomValue",
		"CustomListCustomValueList" => "NetSuite\Classes\CustomListCustomValueList",
		"CustomListTranslations" => "NetSuite\Classes\CustomListTranslations",
		"CustomListTranslationsList" => "NetSuite\Classes\CustomListTranslationsList",
		"CustomRecordType" => "NetSuite\Classes\CustomRecordType",
		"CustomRecordTypeFieldList" => "NetSuite\Classes\CustomRecordTypeFieldList",
		"CustomRecordTypeTabs" => "NetSuite\Classes\CustomRecordTypeTabs",
		"CustomRecordTypeTabsList" => "NetSuite\Classes\CustomRecordTypeTabsList",
		"CustomRecordTypeForms" => "NetSuite\Classes\CustomRecordTypeForms",
		"CustomRecordTypeFormsList" => "NetSuite\Classes\CustomRecordTypeFormsList",
		"CustomRecordTypeOnlineForms" => "NetSuite\Classes\CustomRecordTypeOnlineForms",
		"CustomRecordTypeOnlineFormsList" => "NetSuite\Classes\CustomRecordTypeOnlineFormsList",
		"CustomRecordTypePermissions" => "NetSuite\Classes\CustomRecordTypePermissions",
		"CustomRecordTypePermissionsList" => "NetSuite\Classes\CustomRecordTypePermissionsList",
		"CustomRecordTypeLinks" => "NetSuite\Classes\CustomRecordTypeLinks",
		"CustomRecordTypeLinksList" => "NetSuite\Classes\CustomRecordTypeLinksList",
		"CustomRecordTypeManagers" => "NetSuite\Classes\CustomRecordTypeManagers",
		"CustomRecordTypeManagersList" => "NetSuite\Classes\CustomRecordTypeManagersList",
		"CustomRecordTypeChildren" => "NetSuite\Classes\CustomRecordTypeChildren",
		"CustomRecordTypeChildrenList" => "NetSuite\Classes\CustomRecordTypeChildrenList",
		"CustomRecordTypeParents" => "NetSuite\Classes\CustomRecordTypeParents",
		"CustomRecordTypeParentsList" => "NetSuite\Classes\CustomRecordTypeParentsList",
		"CustomRecordTypeTranslations" => "NetSuite\Classes\CustomRecordTypeTranslations",
		"CustomRecordTypeTranslationsList" => "NetSuite\Classes\CustomRecordTypeTranslationsList",
		"CustomRecordTypeSublists" => "NetSuite\Classes\CustomRecordTypeSublists",
		"CustomRecordTypeSublistsList" => "NetSuite\Classes\CustomRecordTypeSublistsList",
		"CustomFieldType" => "NetSuite\Classes\CustomFieldType",
		"EntityCustomField" => "NetSuite\Classes\EntityCustomField",
		"EntityCustomFieldFilter" => "NetSuite\Classes\EntityCustomFieldFilter",
		"EntityCustomFieldFilterList" => "NetSuite\Classes\EntityCustomFieldFilterList",
		"FldFilterSelList" => "NetSuite\Classes\FldFilterSelList",
		"CrmCustomField" => "NetSuite\Classes\CrmCustomField",
		"CrmCustomFieldFilter" => "NetSuite\Classes\CrmCustomFieldFilter",
		"CrmCustomFieldFilterList" => "NetSuite\Classes\CrmCustomFieldFilterList",
		"OtherCustomField" => "NetSuite\Classes\OtherCustomField",
		"OtherCustomFieldFilter" => "NetSuite\Classes\OtherCustomFieldFilter",
		"OtherCustomFieldFilterList" => "NetSuite\Classes\OtherCustomFieldFilterList",
		"ItemCustomField" => "NetSuite\Classes\ItemCustomField",
		"ItemCustomFieldFilter" => "NetSuite\Classes\ItemCustomFieldFilter",
		"ItemCustomFieldFilterList" => "NetSuite\Classes\ItemCustomFieldFilterList",
		"TransactionBodyCustomField" => "NetSuite\Classes\TransactionBodyCustomField",
		"TransactionBodyCustomFieldFilter" => "NetSuite\Classes\TransactionBodyCustomFieldFilter",
		"TransactionBodyCustomFieldFilterList" => "NetSuite\Classes\TransactionBodyCustomFieldFilterList",
		"TransactionColumnCustomField" => "NetSuite\Classes\TransactionColumnCustomField",
		"TransactionColumnCustomFieldFilter" => "NetSuite\Classes\TransactionColumnCustomFieldFilter",
		"TransactionColumnCustomFieldFilterList" => "NetSuite\Classes\TransactionColumnCustomFieldFilterList",
		"ItemOptionCustomField" => "NetSuite\Classes\ItemOptionCustomField",
		"ItemsList" => "NetSuite\Classes\ItemsList",
		"ItemOptionCustomFieldFilter" => "NetSuite\Classes\ItemOptionCustomFieldFilter",
		"ItemOptionCustomFieldFilterList" => "NetSuite\Classes\ItemOptionCustomFieldFilterList",
		"CustomRecordCustomField" => "NetSuite\Classes\CustomRecordCustomField",
		"CustomRecordCustomFieldFilter" => "NetSuite\Classes\CustomRecordCustomFieldFilter",
		"CustomRecordCustomFieldFilterList" => "NetSuite\Classes\CustomRecordCustomFieldFilterList",
		"CustomFieldRoleAccess" => "NetSuite\Classes\CustomFieldRoleAccess",
		"CustomFieldRoleAccessList" => "NetSuite\Classes\CustomFieldRoleAccessList",
		"CustomFieldDepartmentAccess" => "NetSuite\Classes\CustomFieldDepartmentAccess",
		"CustomFieldDepartmentAccessList" => "NetSuite\Classes\CustomFieldDepartmentAccessList",
		"CustomFieldSubAccess" => "NetSuite\Classes\CustomFieldSubAccess",
		"CustomFieldSubAccessList" => "NetSuite\Classes\CustomFieldSubAccessList",
		"LanguageValue" => "NetSuite\Classes\LanguageValue",
		"LanguageValueList" => "NetSuite\Classes\LanguageValueList",
		"CustomFieldTranslations" => "NetSuite\Classes\CustomFieldTranslations",
		"CustomFieldTranslationsList" => "NetSuite\Classes\CustomFieldTranslationsList",
		"ItemNumberCustomField" => "NetSuite\Classes\ItemNumberCustomField",
		"ItemNumberCustomFieldFilter" => "NetSuite\Classes\ItemNumberCustomFieldFilter",
		"ItemNumberCustomFieldFilterList" => "NetSuite\Classes\ItemNumberCustomFieldFilterList",
		"CustomListSearch" => "NetSuite\Classes\CustomListSearch",
		"CustomListSearchAdvanced" => "NetSuite\Classes\CustomListSearchAdvanced",
		"CustomListSearchRow" => "NetSuite\Classes\CustomListSearchRow",
		"CustomRecordTranslations" => "NetSuite\Classes\CustomRecordTranslations",
		"CustomRecordTranslationsList" => "NetSuite\Classes\CustomRecordTranslationsList",
		"CustomTransaction" => "NetSuite\Classes\CustomTransaction",
		"CustomTransactionLine" => "NetSuite\Classes\CustomTransactionLine",
		"CustomTransactionLineList" => "NetSuite\Classes\CustomTransactionLineList",
		"EmployeePayFrequency" => "NetSuite\Classes\EmployeePayFrequency",
		"EmployeeUseTimeData" => "NetSuite\Classes\EmployeeUseTimeData",
		"EmployeeCommissionPaymentPreference" => "NetSuite\Classes\EmployeeCommissionPaymentPreference",
		"Gender" => "NetSuite\Classes\Gender",
		"EmployeeAccruedTimeAccrualMethod" => "NetSuite\Classes\EmployeeAccruedTimeAccrualMethod",
		"EmployeeDirectDepositAccountStatus" => "NetSuite\Classes\EmployeeDirectDepositAccountStatus",
		"PayrollItemItemTypeNoHierarchy" => "NetSuite\Classes\PayrollItemItemTypeNoHierarchy",
		"EmployeeWorkAssignment" => "NetSuite\Classes\EmployeeWorkAssignment",
		"Employee" => "NetSuite\Classes\Employee",
		"EmployeeSubscriptions" => "NetSuite\Classes\EmployeeSubscriptions",
		"EmployeeSubscriptionsList" => "NetSuite\Classes\EmployeeSubscriptionsList",
		"EmployeeAddressbook" => "NetSuite\Classes\EmployeeAddressbook",
		"EmployeeAddressbookList" => "NetSuite\Classes\EmployeeAddressbookList",
		"EmployeeRoles" => "NetSuite\Classes\EmployeeRoles",
		"EmployeeRolesList" => "NetSuite\Classes\EmployeeRolesList",
		"EmployeeSearch" => "NetSuite\Classes\EmployeeSearch",
		"EmployeeSearchAdvanced" => "NetSuite\Classes\EmployeeSearchAdvanced",
		"EmployeeSearchRow" => "NetSuite\Classes\EmployeeSearchRow",
		"EmployeeEmergencyContact" => "NetSuite\Classes\EmployeeEmergencyContact",
		"EmployeeEmergencyContactList" => "NetSuite\Classes\EmployeeEmergencyContactList",
		"EmployeeHrEducation" => "NetSuite\Classes\EmployeeHrEducation",
		"EmployeeHrEducationList" => "NetSuite\Classes\EmployeeHrEducationList",
		"EmployeeAccruedTime" => "NetSuite\Classes\EmployeeAccruedTime",
		"EmployeeAccruedTimeList" => "NetSuite\Classes\EmployeeAccruedTimeList",
		"EmployeeDeduction" => "NetSuite\Classes\EmployeeDeduction",
		"EmployeeDeductionList" => "NetSuite\Classes\EmployeeDeductionList",
		"EmployeeCompanyContribution" => "NetSuite\Classes\EmployeeCompanyContribution",
		"EmployeeCompanyContributionList" => "NetSuite\Classes\EmployeeCompanyContributionList",
		"EmployeeEarning" => "NetSuite\Classes\EmployeeEarning",
		"EmployeeEarningList" => "NetSuite\Classes\EmployeeEarningList",
		"EmployeeDirectDeposit" => "NetSuite\Classes\EmployeeDirectDeposit",
		"EmployeeDirectDepositList" => "NetSuite\Classes\EmployeeDirectDepositList",
		"PayrollItem" => "NetSuite\Classes\PayrollItem",
		"PayrollItemSearch" => "NetSuite\Classes\PayrollItemSearch",
		"PayrollItemSearchAdvanced" => "NetSuite\Classes\PayrollItemSearchAdvanced",
		"PayrollItemSearchRow" => "NetSuite\Classes\PayrollItemSearchRow",
		"EmployeeRates" => "NetSuite\Classes\EmployeeRates",
		"EmployeeRatesList" => "NetSuite\Classes\EmployeeRatesList",
		"EmployeeHcmPosition" => "NetSuite\Classes\EmployeeHcmPosition",
		"EmployeeHcmPositionList" => "NetSuite\Classes\EmployeeHcmPositionList",
		"MediaType" => "NetSuite\Classes\MediaType",
		"FileAttachFrom" => "NetSuite\Classes\FileAttachFrom",
		"FileEncoding" => "NetSuite\Classes\FileEncoding",
		"TextFileEncoding" => "NetSuite\Classes\TextFileEncoding",
		"FolderFolderType" => "NetSuite\Classes\FolderFolderType",
		"SiteCategoryTranslation" => "NetSuite\Classes\SiteCategoryTranslation",
		"SiteCategoryTranslationList" => "NetSuite\Classes\SiteCategoryTranslationList",
		"SiteCategoryPresentationItemList" => "NetSuite\Classes\SiteCategoryPresentationItemList",
		"SiteCategorySearch" => "NetSuite\Classes\SiteCategorySearch",
		"SiteCategorySearchAdvanced" => "NetSuite\Classes\SiteCategorySearchAdvanced",
		"SiteCategorySearchRow" => "NetSuite\Classes\SiteCategorySearchRow",
		"TimeBillTimeType" => "NetSuite\Classes\TimeBillTimeType",
		"TimeBill" => "NetSuite\Classes\TimeBill",
		"TimeBillSearch" => "NetSuite\Classes\TimeBillSearch",
		"TimeBillSearchAdvanced" => "NetSuite\Classes\TimeBillSearchAdvanced",
		"TimeBillSearchRow" => "NetSuite\Classes\TimeBillSearchRow",
		"ExpenseReport" => "NetSuite\Classes\ExpenseReport",
		"ExpenseReportExpense" => "NetSuite\Classes\ExpenseReportExpense",
		"ExpenseReportExpenseList" => "NetSuite\Classes\ExpenseReportExpenseList",
		"PaycheckJournal" => "NetSuite\Classes\PaycheckJournal",
		"PaycheckJournalCompanyTax" => "NetSuite\Classes\PaycheckJournalCompanyTax",
		"PaycheckJournalCompanyTaxList" => "NetSuite\Classes\PaycheckJournalCompanyTaxList",
		"PaycheckJournalDeduction" => "NetSuite\Classes\PaycheckJournalDeduction",
		"PaycheckJournalDeductionList" => "NetSuite\Classes\PaycheckJournalDeductionList",
		"PaycheckJournalCompanyContribution" => "NetSuite\Classes\PaycheckJournalCompanyContribution",
		"PaycheckJournalCompanyContributionList" => "NetSuite\Classes\PaycheckJournalCompanyContributionList",
		"PaycheckJournalEarning" => "NetSuite\Classes\PaycheckJournalEarning",
		"PaycheckJournalEarningList" => "NetSuite\Classes\PaycheckJournalEarningList",
		"PaycheckJournalEmployeeTax" => "NetSuite\Classes\PaycheckJournalEmployeeTax",
		"PaycheckJournalEmployeeTaxList" => "NetSuite\Classes\PaycheckJournalEmployeeTaxList",
		"TimeEntry" => "NetSuite\Classes\TimeEntry",
		"TimeSheet" => "NetSuite\Classes\TimeSheet",
		"TimeSheetTimeGrid" => "NetSuite\Classes\TimeSheetTimeGrid",
		"TimeSheetTimeGridList" => "NetSuite\Classes\TimeSheetTimeGridList",
		"TimeEntrySearch" => "NetSuite\Classes\TimeEntrySearch",
		"TimeEntrySearchAdvanced" => "NetSuite\Classes\TimeEntrySearchAdvanced",
		"TimeEntrySearchRow" => "NetSuite\Classes\TimeEntrySearchRow",
		"TimeSheetSearch" => "NetSuite\Classes\TimeSheetSearch",
		"TimeSheetSearchAdvanced" => "NetSuite\Classes\TimeSheetSearchAdvanced",
		"TimeSheetSearchRow" => "NetSuite\Classes\TimeSheetSearchRow",
		"CampaignCampaignDirectMailStatus" => "NetSuite\Classes\CampaignCampaignDirectMailStatus",
		"CampaignCampaignEmailStatus" => "NetSuite\Classes\CampaignCampaignEmailStatus",
		"CampaignCampaignEventStatus" => "NetSuite\Classes\CampaignCampaignEventStatus",
		"CampaignChannelEventType" => "NetSuite\Classes\CampaignChannelEventType",
		"CampaignResponseResponse" => "NetSuite\Classes\CampaignResponseResponse",
		"CampaignCampaignEventType" => "NetSuite\Classes\CampaignCampaignEventType",
		"CampaignResponse" => "NetSuite\Classes\CampaignResponse",
		"CampaignStatus" => "NetSuite\Classes\CampaignStatus",
		"PromotionCodeApplyDiscountTo" => "NetSuite\Classes\PromotionCodeApplyDiscountTo",
		"CampaignResponseCategory" => "NetSuite\Classes\CampaignResponseCategory",
		"PromotionCodeUseType" => "NetSuite\Classes\PromotionCodeUseType",
		"Campaign" => "NetSuite\Classes\Campaign",
		"CampaignEmail" => "NetSuite\Classes\CampaignEmail",
		"CampaignEmailList" => "NetSuite\Classes\CampaignEmailList",
		"CampaignDirectMail" => "NetSuite\Classes\CampaignDirectMail",
		"CampaignDirectMailList" => "NetSuite\Classes\CampaignDirectMailList",
		"CampaignEvent" => "NetSuite\Classes\CampaignEvent",
		"CampaignEventList" => "NetSuite\Classes\CampaignEventList",
		"CampaignEventResponse" => "NetSuite\Classes\CampaignEventResponse",
		"CampaignEventResponseList" => "NetSuite\Classes\CampaignEventResponseList",
		"CampaignSearch" => "NetSuite\Classes\CampaignSearch",
		"CampaignSearchAdvanced" => "NetSuite\Classes\CampaignSearchAdvanced",
		"CampaignSearchRow" => "NetSuite\Classes\CampaignSearchRow",
		"CampaignCategory" => "NetSuite\Classes\CampaignCategory",
		"CampaignAudience" => "NetSuite\Classes\CampaignAudience",
		"CampaignFamily" => "NetSuite\Classes\CampaignFamily",
		"CampaignSearchEngine" => "NetSuite\Classes\CampaignSearchEngine",
		"CampaignChannel" => "NetSuite\Classes\CampaignChannel",
		"CampaignOffer" => "NetSuite\Classes\CampaignOffer",
		"CampaignResponseResponses" => "NetSuite\Classes\CampaignResponseResponses",
		"CampaignResponseResponsesList" => "NetSuite\Classes\CampaignResponseResponsesList",
		"CampaignVertical" => "NetSuite\Classes\CampaignVertical",
		"CampaignSubscription" => "NetSuite\Classes\CampaignSubscription",
		"PromotionCode" => "NetSuite\Classes\PromotionCode",
		"PromotionCodePartners" => "NetSuite\Classes\PromotionCodePartners",
		"PromotionCodePartnersList" => "NetSuite\Classes\PromotionCodePartnersList",
		"PromotionCodeItems" => "NetSuite\Classes\PromotionCodeItems",
		"PromotionCodeItemsList" => "NetSuite\Classes\PromotionCodeItemsList",
		"PromotionCodeSearch" => "NetSuite\Classes\PromotionCodeSearch",
		"PromotionCodeSearchAdvanced" => "NetSuite\Classes\PromotionCodeSearchAdvanced",
		"PromotionCodeSearchRow" => "NetSuite\Classes\PromotionCodeSearchRow",
		"PromotionCodeCurrency" => "NetSuite\Classes\PromotionCodeCurrency",
		"PromotionCodeCurrencyList" => "NetSuite\Classes\PromotionCodeCurrencyList",
		"CouponCode" => "NetSuite\Classes\CouponCode",
		"CouponCodeSearch" => "NetSuite\Classes\CouponCodeSearch",
		"CouponCodeSearchAdvanced" => "NetSuite\Classes\CouponCodeSearchAdvanced",
		"CouponCodeSearchRow" => "NetSuite\Classes\CouponCodeSearchRow",
		"DemandPlanCalendarType" => "NetSuite\Classes\DemandPlanCalendarType",
		"DemandPlanMonth" => "NetSuite\Classes\DemandPlanMonth",
		"DayOfTheWeek" => "NetSuite\Classes\DayOfTheWeek",
		"ItemDemandPlanProjectionMethod" => "NetSuite\Classes\ItemDemandPlanProjectionMethod",
		"ItemSupplyPlanOrderType" => "NetSuite\Classes\ItemSupplyPlanOrderType",
		"ItemDemandPlan" => "NetSuite\Classes\ItemDemandPlan",
		"DemandPlan" => "NetSuite\Classes\DemandPlan",
		"DemandPlanMatrix" => "NetSuite\Classes\DemandPlanMatrix",
		"PeriodDemandPlanList" => "NetSuite\Classes\PeriodDemandPlanList",
		"PeriodDemandPlan" => "NetSuite\Classes\PeriodDemandPlan",
		"ItemDemandPlanSearch" => "NetSuite\Classes\ItemDemandPlanSearch",
		"ItemDemandPlanSearchAdvanced" => "NetSuite\Classes\ItemDemandPlanSearchAdvanced",
		"ItemDemandPlanSearchRow" => "NetSuite\Classes\ItemDemandPlanSearchRow",
		"ItemSupplyPlan" => "NetSuite\Classes\ItemSupplyPlan",
		"ItemSupplyPlanOrder" => "NetSuite\Classes\ItemSupplyPlanOrder",
		"ItemSupplyPlanOrderList" => "NetSuite\Classes\ItemSupplyPlanOrderList",
		"ItemSupplyPlanSearch" => "NetSuite\Classes\ItemSupplyPlanSearch",
		"ItemSupplyPlanSearchAdvanced" => "NetSuite\Classes\ItemSupplyPlanSearchAdvanced",
		"ItemSupplyPlanSearchRow" => "NetSuite\Classes\ItemSupplyPlanSearchRow",
		"ManufacturingOperationTaskStatus" => "NetSuite\Classes\ManufacturingOperationTaskStatus",
		"ManufacturingOperationTaskPredecessorPredecessorType" => "NetSuite\Classes\ManufacturingOperationTaskPredecessorPredecessorType",
		"ManufacturingLagType" => "NetSuite\Classes\ManufacturingLagType",
		"ManufacturingCostTemplate" => "NetSuite\Classes\ManufacturingCostTemplate",
		"ManufacturingCostDetail" => "NetSuite\Classes\ManufacturingCostDetail",
		"ManufacturingCostDetailList" => "NetSuite\Classes\ManufacturingCostDetailList",
		"ManufacturingCostTemplateSearch" => "NetSuite\Classes\ManufacturingCostTemplateSearch",
		"ManufacturingCostTemplateSearchAdvanced" => "NetSuite\Classes\ManufacturingCostTemplateSearchAdvanced",
		"ManufacturingCostTemplateSearchRow" => "NetSuite\Classes\ManufacturingCostTemplateSearchRow",
		"ManufacturingRouting" => "NetSuite\Classes\ManufacturingRouting",
		"ManufacturingRoutingRoutingStep" => "NetSuite\Classes\ManufacturingRoutingRoutingStep",
		"ManufacturingRoutingRoutingStepList" => "NetSuite\Classes\ManufacturingRoutingRoutingStepList",
		"ManufacturingRoutingSearch" => "NetSuite\Classes\ManufacturingRoutingSearch",
		"ManufacturingRoutingSearchAdvanced" => "NetSuite\Classes\ManufacturingRoutingSearchAdvanced",
		"ManufacturingRoutingSearchRow" => "NetSuite\Classes\ManufacturingRoutingSearchRow",
		"ManufacturingOperationTask" => "NetSuite\Classes\ManufacturingOperationTask",
		"ManufacturingOperationTaskSearch" => "NetSuite\Classes\ManufacturingOperationTaskSearch",
		"ManufacturingOperationTaskSearchAdvanced" => "NetSuite\Classes\ManufacturingOperationTaskSearchAdvanced",
		"ManufacturingOperationTaskSearchRow" => "NetSuite\Classes\ManufacturingOperationTaskSearchRow",
		"ManufacturingOperationTaskPredecessor" => "NetSuite\Classes\ManufacturingOperationTaskPredecessor",
		"ManufacturingOperationTaskPredecessorList" => "NetSuite\Classes\ManufacturingOperationTaskPredecessorList",
		"ManufacturingRoutingRoutingComponent" => "NetSuite\Classes\ManufacturingRoutingRoutingComponent",
		"ManufacturingRoutingRoutingComponentList" => "NetSuite\Classes\ManufacturingRoutingRoutingComponentList",
	);

	 /*
	 * Constructor using wsdl location and options array
	 * @param string $wsdl WSDL location for this service
	 * @param array $options Options for the SoapClient
	 */
	public function __construct($wsdl=null, $options=array()) {
		parent::__construct($wsdl, $options);
	}

	/**
	 * Service Call: login
	 * Parameter options:
	 * (LoginRequest) parameters
	 * @return LoginResponse
	 * @throws Exception invalid function signature message
	 */
	public function login(Classes\LoginRequest $arg) {
		return $this->makeSoapCall("login", $arg);
	}


	/**
	 * Service Call: ssoLogin
	 * Parameter options:
	 * (SsoLoginRequest) parameters
	 * @return SsoLoginResponse
	 * @throws Exception invalid function signature message
	 */
	public function ssoLogin(Classes\SsoLoginRequest $arg) {
		return $this->makeSoapCall("ssoLogin", $arg);
	}


	/**
	 * Service Call: mapSso
	 * Parameter options:
	 * (MapSsoRequest) parameters
	 * @return MapSsoResponse
	 * @throws Exception invalid function signature message
	 */
	public function mapSso(Classes\MapSsoRequest $arg) {
		return $this->makeSoapCall("mapSso", $arg);
	}


	/**
	 * Service Call: changePassword
	 * Parameter options:
	 * (ChangePasswordRequest) parameters
	 * @return ChangePasswordResponse
	 * @throws Exception invalid function signature message
	 */
	public function changePassword(Classes\ChangePasswordRequest $arg) {
		return $this->makeSoapCall("changePassword", $arg);
	}


	/**
	 * Service Call: changeEmail
	 * Parameter options:
	 * (ChangeEmailRequest) parameters
	 * @return ChangeEmailResponse
	 * @throws Exception invalid function signature message
	 */
	public function changeEmail(Classes\ChangeEmailRequest $arg) {
		return $this->makeSoapCall("changeEmail", $arg);
	}


	/**
	 * Service Call: logout
	 * Parameter options:
	 * (LogoutRequest) parameters
	 * @return LogoutResponse
	 * @throws Exception invalid function signature message
	 */
	public function logout(Classes\LogoutRequest $arg) {
		return $this->makeSoapCall("logout", $arg);
	}


	/**
	 * Service Call: add
	 * Parameter options:
	 * (AddRequest) parameters
	 * @return AddResponse
	 * @throws Exception invalid function signature message
	 */
	public function add(Classes\AddRequest $arg) {
		return $this->makeSoapCall("add", $arg);
	}


	/**
	 * Service Call: delete
	 * Parameter options:
	 * (DeleteRequest) parameters
	 * @return DeleteResponse
	 * @throws Exception invalid function signature message
	 */
	public function delete(Classes\DeleteRequest $arg) {
		return $this->makeSoapCall("delete", $arg);
	}


	/**
	 * Service Call: search
	 * Parameter options:
	 * (SearchRequest) parameters
	 * @return SearchResponse
	 * @throws Exception invalid function signature message
	 */
	public function search(Classes\SearchRequest $arg) {
		return $this->makeSoapCall("search", $arg);
	}


	/**
	 * Service Call: searchMore
	 * Parameter options:
	 * (SearchMoreRequest) parameters
	 * @return SearchMoreResponse
	 * @throws Exception invalid function signature message
	 */
	public function searchMore(Classes\SearchMoreRequest $arg) {
		return $this->makeSoapCall("searchMore", $arg);
	}


	/**
	 * Service Call: searchMoreWithId
	 * Parameter options:
	 * (SearchMoreWithIdRequest) parameters
	 * @return SearchMoreWithIdResponse
	 * @throws Exception invalid function signature message
	 */
	public function searchMoreWithId(Classes\SearchMoreWithIdRequest $arg) {
		return $this->makeSoapCall("searchMoreWithId", $arg);
	}


	/**
	 * Service Call: searchNext
	 * Parameter options:
	 * (SearchNextRequest) parameters
	 * @return SearchNextResponse
	 * @throws Exception invalid function signature message
	 */
	public function searchNext(Classes\SearchNextRequest $arg) {
		return $this->makeSoapCall("searchNext", $arg);
	}


	/**
	 * Service Call: update
	 * Parameter options:
	 * (UpdateRequest) parameters
	 * @return UpdateResponse
	 * @throws Exception invalid function signature message
	 */
	public function update(Classes\UpdateRequest $arg) {
		return $this->makeSoapCall("update", $arg);
	}


	/**
	 * Service Call: upsert
	 * Parameter options:
	 * (UpsertRequest) parameters
	 * @return UpsertResponse
	 * @throws Exception invalid function signature message
	 */
	public function upsert(Classes\UpsertRequest $arg) {
		return $this->makeSoapCall("upsert", $arg);
	}


	/**
	 * Service Call: addList
	 * Parameter options:
	 * (AddListRequest) parameters
	 * @return AddListResponse
	 * @throws Exception invalid function signature message
	 */
	public function addList(Classes\AddListRequest $arg) {
		return $this->makeSoapCall("addList", $arg);
	}


	/**
	 * Service Call: deleteList
	 * Parameter options:
	 * (DeleteListRequest) parameters
	 * @return DeleteListResponse
	 * @throws Exception invalid function signature message
	 */
	public function deleteList(Classes\DeleteListRequest $arg) {
		return $this->makeSoapCall("deleteList", $arg);
	}


	/**
	 * Service Call: updateList
	 * Parameter options:
	 * (UpdateListRequest) parameters
	 * @return UpdateListResponse
	 * @throws Exception invalid function signature message
	 */
	public function updateList(Classes\UpdateListRequest $arg) {
		return $this->makeSoapCall("updateList", $arg);
	}


	/**
	 * Service Call: upsertList
	 * Parameter options:
	 * (UpsertListRequest) parameters
	 * @return UpsertListResponse
	 * @throws Exception invalid function signature message
	 */
	public function upsertList(Classes\UpsertListRequest $arg) {
		return $this->makeSoapCall("upsertList", $arg);
	}


	/**
	 * Service Call: get
	 * Parameter options:
	 * (GetRequest) parameters
	 * @return GetResponse
	 * @throws Exception invalid function signature message
	 */
	public function get(Classes\GetRequest $arg) {
		return $this->makeSoapCall("get", $arg);
	}


	/**
	 * Service Call: getList
	 * Parameter options:
	 * (GetListRequest) parameters
	 * @return GetListResponse
	 * @throws Exception invalid function signature message
	 */
	public function getList(Classes\GetListRequest $arg) {
		return $this->makeSoapCall("getList", $arg);
	}


	/**
	 * Service Call: getAll
	 * Parameter options:
	 * (GetAllRequest) parameters
	 * @return GetAllResponse
	 * @throws Exception invalid function signature message
	 */
	public function getAll(Classes\GetAllRequest $arg) {
		return $this->makeSoapCall("getAll", $arg);
	}


	/**
	 * Service Call: getSavedSearch
	 * Parameter options:
	 * (GetSavedSearchRequest) parameters
	 * @return GetSavedSearchResponse
	 * @throws Exception invalid function signature message
	 */
	public function getSavedSearch(Classes\GetSavedSearchRequest $arg) {
		return $this->makeSoapCall("getSavedSearch", $arg);
	}


	/**
	 * Service Call: getCustomizationId
	 * Parameter options:
	 * (GetCustomizationIdRequest) parameters
	 * @return GetCustomizationIdResponse
	 * @throws Exception invalid function signature message
	 */
	public function getCustomizationId(Classes\GetCustomizationIdRequest $arg) {
		return $this->makeSoapCall("getCustomizationId", $arg);
	}


	/**
	 * Service Call: initialize
	 * Parameter options:
	 * (InitializeRequest) parameters
	 * @return InitializeResponse
	 * @throws Exception invalid function signature message
	 */
	public function initialize(Classes\InitializeRequest $arg) {
		return $this->makeSoapCall("initialize", $arg);
	}


	/**
	 * Service Call: initializeList
	 * Parameter options:
	 * (InitializeListRequest) parameters
	 * @return InitializeListResponse
	 * @throws Exception invalid function signature message
	 */
	public function initializeList(Classes\InitializeListRequest $arg) {
		return $this->makeSoapCall("initializeList", $arg);
	}


	/**
	 * Service Call: getSelectValue
	 * Parameter options:
	 * (getSelectValueRequest) parameters
	 * @return getSelectValueResponse
	 * @throws Exception invalid function signature message
	 */
	public function getSelectValue(Classes\getSelectValueRequest $arg) {
		return $this->makeSoapCall("getSelectValue", $arg);
	}


	/**
	 * Service Call: getItemAvailability
	 * Parameter options:
	 * (GetItemAvailabilityRequest) parameters
	 * @return GetItemAvailabilityResponse
	 * @throws Exception invalid function signature message
	 */
	public function getItemAvailability(Classes\GetItemAvailabilityRequest $arg) {
		return $this->makeSoapCall("getItemAvailability", $arg);
	}


	/**
	 * Service Call: getBudgetExchangeRate
	 * Parameter options:
	 * (GetBudgetExchangeRateRequest) parameters
	 * @return GetBudgetExchangeRateResponse
	 * @throws Exception invalid function signature message
	 */
	public function getBudgetExchangeRate(Classes\GetBudgetExchangeRateRequest $arg) {
		return $this->makeSoapCall("getBudgetExchangeRate", $arg);
	}


	/**
	 * Service Call: getCurrencyRate
	 * Parameter options:
	 * (GetCurrencyRateRequest) parameters
	 * @return GetCurrencyRateResponse
	 * @throws Exception invalid function signature message
	 */
	public function getCurrencyRate(Classes\GetCurrencyRateRequest $arg) {
		return $this->makeSoapCall("getCurrencyRate", $arg);
	}


	/**
	 * Service Call: getDataCenterUrls
	 * Parameter options:
	 * (GetDataCenterUrlsRequest) parameters
	 * @return GetDataCenterUrlsResponse
	 * @throws Exception invalid function signature message
	 */
	public function getDataCenterUrls(Classes\GetDataCenterUrlsRequest $arg) {
		return $this->makeSoapCall("getDataCenterUrls", $arg);
	}


	/**
	 * Service Call: getPostingTransactionSummary
	 * Parameter options:
	 * (GetPostingTransactionSummaryRequest) parameters
	 * @return GetPostingTransactionSummaryResponse
	 * @throws Exception invalid function signature message
	 */
	public function getPostingTransactionSummary(Classes\GetPostingTransactionSummaryRequest $arg) {
		return $this->makeSoapCall("getPostingTransactionSummary", $arg);
	}


	/**
	 * Service Call: getServerTime
	 * Parameter options:
	 * (GetServerTimeRequest) parameters
	 * @return GetServerTimeResponse
	 * @throws Exception invalid function signature message
	 */
	public function getServerTime(Classes\GetServerTimeRequest $arg) {
		return $this->makeSoapCall("getServerTime", $arg);
	}


	/**
	 * Service Call: attach
	 * Parameter options:
	 * (AttachRequest) parameters
	 * @return AttachResponse
	 * @throws Exception invalid function signature message
	 */
	public function attach(Classes\AttachRequest $arg) {
		return $this->makeSoapCall("attach", $arg);
	}


	/**
	 * Service Call: detach
	 * Parameter options:
	 * (DetachRequest) parameters
	 * @return DetachResponse
	 * @throws Exception invalid function signature message
	 */
	public function detach(Classes\DetachRequest $arg) {
		return $this->makeSoapCall("detach", $arg);
	}


	/**
	 * Service Call: updateInviteeStatus
	 * Parameter options:
	 * (UpdateInviteeStatusRequest) parameters
	 * @return UpdateInviteeStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function updateInviteeStatus(Classes\UpdateInviteeStatusRequest $arg) {
		return $this->makeSoapCall("updateInviteeStatus", $arg);
	}


	/**
	 * Service Call: updateInviteeStatusList
	 * Parameter options:
	 * (UpdateInviteeStatusListRequest) parameters
	 * @return UpdateInviteeStatusListResponse
	 * @throws Exception invalid function signature message
	 */
	public function updateInviteeStatusList(Classes\UpdateInviteeStatusListRequest $arg) {
		return $this->makeSoapCall("updateInviteeStatusList", $arg);
	}


	/**
	 * Service Call: asyncAddList
	 * Parameter options:
	 * (AsyncAddListRequest) parameters
	 * @return AsyncStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function asyncAddList(Classes\AsyncAddListRequest $arg) {
		return $this->makeSoapCall("asyncAddList", $arg);
	}


	/**
	 * Service Call: asyncUpdateList
	 * Parameter options:
	 * (AsyncUpdateListRequest) parameters
	 * @return AsyncStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function asyncUpdateList(Classes\AsyncUpdateListRequest $arg) {
		return $this->makeSoapCall("asyncUpdateList", $arg);
	}


	/**
	 * Service Call: asyncUpsertList
	 * Parameter options:
	 * (AsyncUpsertListRequest) parameters
	 * @return AsyncStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function asyncUpsertList(Classes\AsyncUpsertListRequest $arg) {
		return $this->makeSoapCall("asyncUpsertList", $arg);
	}


	/**
	 * Service Call: asyncDeleteList
	 * Parameter options:
	 * (AsyncDeleteListRequest) parameters
	 * @return AsyncStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function asyncDeleteList(Classes\AsyncDeleteListRequest $arg) {
		return $this->makeSoapCall("asyncDeleteList", $arg);
	}


	/**
	 * Service Call: asyncGetList
	 * Parameter options:
	 * (AsyncGetListRequest) parameters
	 * @return AsyncStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function asyncGetList(Classes\AsyncGetListRequest $arg) {
		return $this->makeSoapCall("asyncGetList", $arg);
	}


	/**
	 * Service Call: asyncInitializeList
	 * Parameter options:
	 * (AsyncInitializeListRequest) parameters
	 * @return AsyncStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function asyncInitializeList(Classes\AsyncInitializeListRequest $arg) {
		return $this->makeSoapCall("asyncInitializeList", $arg);
	}


	/**
	 * Service Call: asyncSearch
	 * Parameter options:
	 * (AsyncSearchRequest) parameters
	 * @return AsyncStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function asyncSearch(Classes\AsyncSearchRequest $arg) {
		return $this->makeSoapCall("asyncSearch", $arg);
	}


	/**
	 * Service Call: getAsyncResult
	 * Parameter options:
	 * (GetAsyncResultRequest) parameters
	 * @return GetAsyncResultResponse
	 * @throws Exception invalid function signature message
	 */
	public function getAsyncResult(Classes\GetAsyncResultRequest $arg) {
		return $this->makeSoapCall("getAsyncResult", $arg);
	}


	/**
	 * Service Call: checkAsyncStatus
	 * Parameter options:
	 * (CheckAsyncStatusRequest) parameters
	 * @return AsyncStatusResponse
	 * @throws Exception invalid function signature message
	 */
	public function checkAsyncStatus(Classes\CheckAsyncStatusRequest $arg) {
		return $this->makeSoapCall("checkAsyncStatus", $arg);
	}


	/**
	 * Service Call: getDeleted
	 * Parameter options:
	 * (GetDeletedRequest) parameters
	 * @return GetDeletedResponse
	 * @throws Exception invalid function signature message
	 */
	public function getDeleted(Classes\GetDeletedRequest $arg) {
		return $this->makeSoapCall("getDeleted", $arg);
	}
}
