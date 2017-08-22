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
		"RecordType" => "RecordType",
		"SearchRecordType" => "SearchRecordType",
		"GetAllRecordType" => "GetAllRecordType",
		"GetCustomizationType" => "GetCustomizationType",
		"InitializeType" => "InitializeType",
		"InitializeRefType" => "InitializeRefType",
		"InitializeAuxRefType" => "InitializeAuxRefType",
		"DeletedRecordType" => "DeletedRecordType",
		"AsyncStatusType" => "AsyncStatusType",
		"SearchStringFieldOperator" => "SearchStringFieldOperator",
		"SearchLongFieldOperator" => "SearchLongFieldOperator",
		"SearchTextNumberFieldOperator" => "SearchTextNumberFieldOperator",
		"SearchDoubleFieldOperator" => "SearchDoubleFieldOperator",
		"SearchDateFieldOperator" => "SearchDateFieldOperator",
		"SearchEnumMultiSelectFieldOperator" => "SearchEnumMultiSelectFieldOperator",
		"SearchMultiSelectFieldOperator" => "SearchMultiSelectFieldOperator",
		"SearchDate" => "SearchDate",
		"DurationUnit" => "DurationUnit",
		"CalendarEventAttendeeResponse" => "CalendarEventAttendeeResponse",
		"GetSelectValueFilterOperator" => "GetSelectValueFilterOperator",
		"SignatureAlgorithm" => "SignatureAlgorithm",
		"StatusDetailType" => "StatusDetailType",
		"StatusDetailCodeType" => "StatusDetailCodeType",
		"FaultCodeType" => "FaultCodeType",
		"Passport" => "Passport",
		"SsoPassport" => "SsoPassport",
		"SsoCredentials" => "SsoCredentials",
		"TokenPassportSignature" => "TokenPassportSignature",
		"TokenPassport" => "TokenPassport",
		"ChangePassword" => "ChangePassword",
		"ChangeEmail" => "ChangeEmail",
		"StatusDetail" => "StatusDetail",
		"Status" => "Status",
		"WsRole" => "WsRole",
		"WsRoleList" => "WsRoleList",
		"Record" => "Record",
		"NullField" => "NullField",
		"SearchRecord" => "SearchRecord",
		"SearchRecordBasic" => "SearchRecordBasic",
		"SearchRow" => "SearchRow",
		"SearchRowBasic" => "SearchRowBasic",
		"SearchResult" => "SearchResult",
		"AsyncStatusResult" => "AsyncStatusResult",
		"GetAllResult" => "GetAllResult",
		"GetSavedSearchResult" => "GetSavedSearchResult",
		"GetCustomizationIdResult" => "GetCustomizationIdResult",
		"GetSelectValueResult" => "GetSelectValueResult",
		"RecordList" => "RecordList",
		"SearchRowList" => "SearchRowList",
		"RecordRefList" => "RecordRefList",
		"BaseRef" => "BaseRef",
		"BaseRefList" => "BaseRefList",
		"RecordRef" => "RecordRef",
		"Duration" => "Duration",
		"CustomRecordRef" => "CustomRecordRef",
		"CustomTransactionRef" => "CustomTransactionRef",
		"CustomizationRef" => "CustomizationRef",
		"CustomizationRefList" => "CustomizationRefList",
		"InitializeRecord" => "InitializeRecord",
		"InitializeRef" => "InitializeRef",
		"InitializeRefList" => "InitializeRefList",
		"InitializeAuxRef" => "InitializeAuxRef",
		"UpdateInviteeStatusReference" => "UpdateInviteeStatusReference",
		"GetAllRecord" => "GetAllRecord",
		"GetSavedSearchRecord" => "GetSavedSearchRecord",
		"CustomizationType" => "CustomizationType",
		"ListOrRecordRef" => "ListOrRecordRef",
		"CustomFieldRef" => "CustomFieldRef",
		"LongCustomFieldRef" => "LongCustomFieldRef",
		"DoubleCustomFieldRef" => "DoubleCustomFieldRef",
		"BooleanCustomFieldRef" => "BooleanCustomFieldRef",
		"StringCustomFieldRef" => "StringCustomFieldRef",
		"DateCustomFieldRef" => "DateCustomFieldRef",
		"SelectCustomFieldRef" => "SelectCustomFieldRef",
		"MultiSelectCustomFieldRef" => "MultiSelectCustomFieldRef",
		"CustomFieldList" => "CustomFieldList",
		"DimensionRef" => "DimensionRef",
		"StringDimensionRef" => "StringDimensionRef",
		"SelectDimensionRef" => "SelectDimensionRef",
		"DimensionList" => "DimensionList",
		"SearchBooleanField" => "SearchBooleanField",
		"SearchStringField" => "SearchStringField",
		"SearchLongField" => "SearchLongField",
		"SearchTextNumberField" => "SearchTextNumberField",
		"SearchDoubleField" => "SearchDoubleField",
		"SearchDateField" => "SearchDateField",
		"SearchEnumMultiSelectField" => "SearchEnumMultiSelectField",
		"SearchMultiSelectField" => "SearchMultiSelectField",
		"SearchCustomField" => "SearchCustomField",
		"SearchBooleanCustomField" => "SearchBooleanCustomField",
		"SearchStringCustomField" => "SearchStringCustomField",
		"SearchLongCustomField" => "SearchLongCustomField",
		"SearchDoubleCustomField" => "SearchDoubleCustomField",
		"SearchDateCustomField" => "SearchDateCustomField",
		"SearchEnumMultiSelectCustomField" => "SearchEnumMultiSelectCustomField",
		"SearchMultiSelectCustomField" => "SearchMultiSelectCustomField",
		"SearchCustomFieldList" => "SearchCustomFieldList",
		"SearchColumnField" => "SearchColumnField",
		"SearchColumnBooleanField" => "SearchColumnBooleanField",
		"SearchColumnStringField" => "SearchColumnStringField",
		"SearchColumnLongField" => "SearchColumnLongField",
		"SearchColumnTextNumberField" => "SearchColumnTextNumberField",
		"SearchColumnDoubleField" => "SearchColumnDoubleField",
		"SearchColumnDateField" => "SearchColumnDateField",
		"SearchColumnEnumSelectField" => "SearchColumnEnumSelectField",
		"SearchColumnSelectField" => "SearchColumnSelectField",
		"SearchColumnCustomField" => "SearchColumnCustomField",
		"SearchColumnBooleanCustomField" => "SearchColumnBooleanCustomField",
		"SearchColumnStringCustomField" => "SearchColumnStringCustomField",
		"SearchColumnLongCustomField" => "SearchColumnLongCustomField",
		"SearchColumnDoubleCustomField" => "SearchColumnDoubleCustomField",
		"SearchColumnDateCustomField" => "SearchColumnDateCustomField",
		"SearchColumnEnumMultiSelectCustomField" => "SearchColumnEnumMultiSelectCustomField",
		"SearchColumnSelectCustomField" => "SearchColumnSelectCustomField",
		"SearchColumnMultiSelectCustomField" => "SearchColumnMultiSelectCustomField",
		"SearchColumnCustomFieldList" => "SearchColumnCustomFieldList",
		"ItemAvailabilityFilter" => "ItemAvailabilityFilter",
		"ItemAvailability" => "ItemAvailability",
		"ItemAvailabilityList" => "ItemAvailabilityList",
		"GetItemAvailabilityResult" => "GetItemAvailabilityResult",
		"BudgetExchangeRateFilter" => "BudgetExchangeRateFilter",
		"BudgetExchangeRate" => "BudgetExchangeRate",
		"BudgetExchangeRateList" => "BudgetExchangeRateList",
		"GetBudgetExchangeRateResult" => "GetBudgetExchangeRateResult",
		"CurrencyRateFilter" => "CurrencyRateFilter",
		"CurrencyRate" => "CurrencyRate",
		"CurrencyRateList" => "CurrencyRateList",
		"GetCurrencyRateResult" => "GetCurrencyRateResult",
		"DataCenterUrls" => "DataCenterUrls",
		"GetDataCenterUrlsResult" => "GetDataCenterUrlsResult",
		"PostingTransactionSummaryField" => "PostingTransactionSummaryField",
		"PostingTransactionSummaryFilter" => "PostingTransactionSummaryFilter",
		"PostingTransactionSummary" => "PostingTransactionSummary",
		"PostingTransactionSummaryList" => "PostingTransactionSummaryList",
		"GetPostingTransactionSummaryResult" => "GetPostingTransactionSummaryResult",
		"GetSelectValueFieldDescription" => "GetSelectValueFieldDescription",
		"GetSelectValueFilter" => "GetSelectValueFilter",
		"GetSelectFilterByFieldValueList" => "GetSelectFilterByFieldValueList",
		"GetSelectFilterByFieldValue" => "GetSelectFilterByFieldValue",
		"GetServerTimeResult" => "GetServerTimeResult",
		"DeletedRecord" => "DeletedRecord",
		"DeletedRecordList" => "DeletedRecordList",
		"GetDeletedResult" => "GetDeletedResult",
		"GetDeletedFilter" => "GetDeletedFilter",
		"AttachReference" => "AttachReference",
		"DetachReference" => "DetachReference",
		"AttachContactReference" => "AttachContactReference",
		"AttachBasicReference" => "AttachBasicReference",
		"DetachBasicReference" => "DetachBasicReference",
		"DeletionReason" => "DeletionReason",
		"SoapFault" => "NSSoapFault",
		"InsufficientPermissionFault" => "InsufficientPermissionFault",
		"InvalidAccountFault" => "InvalidAccountFault",
		"InvalidCredentialsFault" => "InvalidCredentialsFault",
		"InvalidSessionFault" => "InvalidSessionFault",
		"ExceededConcurrentRequestLimitFault" => "ExceededConcurrentRequestLimitFault",
		"ExceededRequestLimitFault" => "ExceededRequestLimitFault",
		"ExceededUsageLimitFault" => "ExceededUsageLimitFault",
		"ExceededRecordCountFault" => "ExceededRecordCountFault",
		"InvalidVersionFault" => "InvalidVersionFault",
		"ExceededRequestSizeFault" => "ExceededRequestSizeFault",
		"AsyncFault" => "AsyncFault",
		"UnexpectedErrorFault" => "UnexpectedErrorFault",
		"ApplicationInfo" => "ApplicationInfo",
		"PartnerInfo" => "PartnerInfo",
		"DocumentInfo" => "DocumentInfo",
		"Preferences" => "Preferences",
		"SearchPreferences" => "SearchPreferences",
		"SessionResponse" => "SessionResponse",
		"WriteResponse" => "WriteResponse",
		"ReadResponse" => "ReadResponse",
		"WriteResponseList" => "WriteResponseList",
		"ReadResponseList" => "ReadResponseList",
		"LoginResponse" => "LoginResponse",
		"SsoLoginResponse" => "SsoLoginResponse",
		"MapSsoResponse" => "MapSsoResponse",
		"ChangePasswordResponse" => "ChangePasswordResponse",
		"ChangeEmailResponse" => "ChangeEmailResponse",
		"LogoutResponse" => "LogoutResponse",
		"AddResponse" => "AddResponse",
		"AddListResponse" => "AddListResponse",
		"UpdateResponse" => "UpdateResponse",
		"UpdateListResponse" => "UpdateListResponse",
		"UpsertResponse" => "UpsertResponse",
		"UpsertListResponse" => "UpsertListResponse",
		"DeleteResponse" => "DeleteResponse",
		"DeleteListResponse" => "DeleteListResponse",
		"SearchResponse" => "SearchResponse",
		"SearchMoreResponse" => "SearchMoreResponse",
		"SearchMoreWithIdResponse" => "SearchMoreWithIdResponse",
		"SearchNextResponse" => "SearchNextResponse",
		"GetResponse" => "GetResponse",
		"GetListResponse" => "GetListResponse",
		"GetAllResponse" => "GetAllResponse",
		"GetSavedSearchResponse" => "GetSavedSearchResponse",
		"GetCustomizationIdResponse" => "GetCustomizationIdResponse",
		"InitializeResponse" => "InitializeResponse",
		"InitializeListResponse" => "InitializeListResponse",
		"getSelectValueResponse" => "getSelectValueResponse",
		"GetItemAvailabilityResponse" => "GetItemAvailabilityResponse",
		"GetBudgetExchangeRateResponse" => "GetBudgetExchangeRateResponse",
		"GetCurrencyRateResponse" => "GetCurrencyRateResponse",
		"GetDataCenterUrlsResponse" => "GetDataCenterUrlsResponse",
		"GetPostingTransactionSummaryResponse" => "GetPostingTransactionSummaryResponse",
		"GetServerTimeResponse" => "GetServerTimeResponse",
		"AttachResponse" => "AttachResponse",
		"DetachResponse" => "DetachResponse",
		"UpdateInviteeStatusResponse" => "UpdateInviteeStatusResponse",
		"UpdateInviteeStatusListResponse" => "UpdateInviteeStatusListResponse",
		"AsyncStatusResponse" => "AsyncStatusResponse",
		"GetAsyncResultResponse" => "GetAsyncResultResponse",
		"AsyncResult" => "AsyncResult",
		"AsyncAddListResult" => "AsyncAddListResult",
		"AsyncUpdateListResult" => "AsyncUpdateListResult",
		"AsyncUpsertListResult" => "AsyncUpsertListResult",
		"AsyncDeleteListResult" => "AsyncDeleteListResult",
		"AsyncGetListResult" => "AsyncGetListResult",
		"AsyncSearchResult" => "AsyncSearchResult",
		"AsyncInitializeListResult" => "AsyncInitializeListResult",
		"GetDeletedResponse" => "GetDeletedResponse",
		"LoginRequest" => "LoginRequest",
		"SsoLoginRequest" => "SsoLoginRequest",
		"MapSsoRequest" => "MapSsoRequest",
		"ChangePasswordRequest" => "ChangePasswordRequest",
		"ChangeEmailRequest" => "ChangeEmailRequest",
		"LogoutRequest" => "LogoutRequest",
		"AddRequest" => "AddRequest",
		"DeleteRequest" => "DeleteRequest",
		"SearchRequest" => "SearchRequest",
		"SearchMoreRequest" => "SearchMoreRequest",
		"SearchMoreWithIdRequest" => "SearchMoreWithIdRequest",
		"SearchNextRequest" => "SearchNextRequest",
		"UpdateRequest" => "UpdateRequest",
		"UpsertRequest" => "UpsertRequest",
		"AddListRequest" => "AddListRequest",
		"DeleteListRequest" => "DeleteListRequest",
		"UpdateListRequest" => "UpdateListRequest",
		"UpsertListRequest" => "UpsertListRequest",
		"GetRequest" => "GetRequest",
		"GetListRequest" => "GetListRequest",
		"GetAllRequest" => "GetAllRequest",
		"GetSavedSearchRequest" => "GetSavedSearchRequest",
		"GetCustomizationIdRequest" => "GetCustomizationIdRequest",
		"InitializeRequest" => "InitializeRequest",
		"InitializeListRequest" => "InitializeListRequest",
		"getSelectValueRequest" => "getSelectValueRequest",
		"GetItemAvailabilityRequest" => "GetItemAvailabilityRequest",
		"GetBudgetExchangeRateRequest" => "GetBudgetExchangeRateRequest",
		"GetCurrencyRateRequest" => "GetCurrencyRateRequest",
		"GetDataCenterUrlsRequest" => "GetDataCenterUrlsRequest",
		"GetPostingTransactionSummaryRequest" => "GetPostingTransactionSummaryRequest",
		"GetServerTimeRequest" => "GetServerTimeRequest",
		"AttachRequest" => "AttachRequest",
		"DetachRequest" => "DetachRequest",
		"AsyncAddListRequest" => "AsyncAddListRequest",
		"UpdateInviteeStatusRequest" => "UpdateInviteeStatusRequest",
		"UpdateInviteeStatusListRequest" => "UpdateInviteeStatusListRequest",
		"AsyncUpdateListRequest" => "AsyncUpdateListRequest",
		"AsyncUpsertListRequest" => "AsyncUpsertListRequest",
		"AsyncDeleteListRequest" => "AsyncDeleteListRequest",
		"AsyncGetListRequest" => "AsyncGetListRequest",
		"AsyncInitializeListRequest" => "AsyncInitializeListRequest",
		"AsyncSearchRequest" => "AsyncSearchRequest",
		"CheckAsyncStatusRequest" => "CheckAsyncStatusRequest",
		"GetAsyncResultRequest" => "GetAsyncResultRequest",
		"GetDeletedRequest" => "GetDeletedRequest",
		"Country" => "Country",
		"Language" => "Language",
		"AvsMatchCode" => "AvsMatchCode",
		"CscMatchCode" => "CscMatchCode",
		"VsoeSopGroup" => "VsoeSopGroup",
		"VsoeDeferral" => "VsoeDeferral",
		"VsoePermitDiscount" => "VsoePermitDiscount",
		"RevenueStatus" => "RevenueStatus",
		"RevenueCommitStatus" => "RevenueCommitStatus",
		"PostingPeriodDate" => "PostingPeriodDate",
		"PermissionLevel" => "PermissionLevel",
		"Source" => "Source",
		"GlobalSubscriptionStatus" => "GlobalSubscriptionStatus",
		"ItemCostEstimateType" => "ItemCostEstimateType",
		"PresentationItemType" => "PresentationItemType",
		"LandedCostSource" => "LandedCostSource",
		"LandedCostMethod" => "LandedCostMethod",
		"SitemapPriority" => "SitemapPriority",
		"TimeItemTimeType" => "TimeItemTimeType",
		"PermissionCode" => "PermissionCode",
		"IntercoStatus" => "IntercoStatus",
		"CurrencySymbolPlacement" => "CurrencySymbolPlacement",
		"RecurrenceFrequency" => "RecurrenceFrequency",
		"RecurrenceDow" => "RecurrenceDow",
		"RecurrenceDowim" => "RecurrenceDowim",
		"AlcoholRecipientType" => "AlcoholRecipientType",
		"ShippingCarrier" => "ShippingCarrier",
		"ItemSource" => "ItemSource",
		"Address" => "Address",
		"PresentationItem" => "PresentationItem",
		"Partners" => "Partners",
		"LandedCost" => "LandedCost",
		"LandedCostDataList" => "LandedCostDataList",
		"LandedCostData" => "LandedCostData",
		"LandedCostSummary" => "LandedCostSummary",
		"CustomerSalesTeam" => "CustomerSalesTeam",
		"TimeItem" => "TimeItem",
		"InventoryDetail" => "InventoryDetail",
		"RecurrenceDowMaskList" => "RecurrenceDowMaskList",
		"AccountingBookDetail" => "AccountingBookDetail",
		"AccountingBookDetailList" => "AccountingBookDetailList",
		"InventoryAssignmentList" => "InventoryAssignmentList",
		"InventoryAssignment" => "InventoryAssignment",
		"InventoryDetailSearchBasic" => "InventoryDetailSearchBasic",
		"InventoryDetailSearchRowBasic" => "InventoryDetailSearchRowBasic",
		"EntitySearchBasic" => "EntitySearchBasic",
		"EntitySearchRowBasic" => "EntitySearchRowBasic",
		"ContactSearchBasic" => "ContactSearchBasic",
		"ContactSearchRowBasic" => "ContactSearchRowBasic",
		"CustomerSearchBasic" => "CustomerSearchBasic",
		"CustomerSearchRowBasic" => "CustomerSearchRowBasic",
		"CalendarEventSearchBasic" => "CalendarEventSearchBasic",
		"CalendarEventSearchRowBasic" => "CalendarEventSearchRowBasic",
		"TaskSearchBasic" => "TaskSearchBasic",
		"TaskSearchRowBasic" => "TaskSearchRowBasic",
		"OpportunitySearchBasic" => "OpportunitySearchBasic",
		"OpportunitySearchRowBasic" => "OpportunitySearchRowBasic",
		"EmployeeSearchBasic" => "EmployeeSearchBasic",
		"EmployeeSearchRowBasic" => "EmployeeSearchRowBasic",
		"PhoneCallSearchBasic" => "PhoneCallSearchBasic",
		"PhoneCallSearchRowBasic" => "PhoneCallSearchRowBasic",
		"SupportCaseSearchBasic" => "SupportCaseSearchBasic",
		"SupportCaseSearchRowBasic" => "SupportCaseSearchRowBasic",
		"MessageSearchBasic" => "MessageSearchBasic",
		"MessageSearchRowBasic" => "MessageSearchRowBasic",
		"NoteSearchBasic" => "NoteSearchBasic",
		"NoteSearchRowBasic" => "NoteSearchRowBasic",
		"CustomRecordSearchBasic" => "CustomRecordSearchBasic",
		"CustomRecordSearchRowBasic" => "CustomRecordSearchRowBasic",
		"AccountSearchBasic" => "AccountSearchBasic",
		"AccountSearchRowBasic" => "AccountSearchRowBasic",
		"RevRecScheduleSearchBasic" => "RevRecScheduleSearchBasic",
		"RevRecScheduleSearchRowBasic" => "RevRecScheduleSearchRowBasic",
		"RevRecTemplateSearchBasic" => "RevRecTemplateSearchBasic",
		"RevRecTemplateSearchRowBasic" => "RevRecTemplateSearchRowBasic",
		"BinSearchBasic" => "BinSearchBasic",
		"BinSearchRowBasic" => "BinSearchRowBasic",
		"DepartmentSearchBasic" => "DepartmentSearchBasic",
		"DepartmentSearchRowBasic" => "DepartmentSearchRowBasic",
		"LocationSearchBasic" => "LocationSearchBasic",
		"LocationSearchRowBasic" => "LocationSearchRowBasic",
		"ClassificationSearchBasic" => "ClassificationSearchBasic",
		"ClassificationSearchRowBasic" => "ClassificationSearchRowBasic",
		"TransactionSearchBasic" => "TransactionSearchBasic",
		"TransactionSearchRowBasic" => "TransactionSearchRowBasic",
		"ItemSearchBasic" => "ItemSearchBasic",
		"ItemSearchRowBasic" => "ItemSearchRowBasic",
		"PartnerSearchBasic" => "PartnerSearchBasic",
		"PartnerSearchRowBasic" => "PartnerSearchRowBasic",
		"VendorSearchBasic" => "VendorSearchBasic",
		"VendorSearchRowBasic" => "VendorSearchRowBasic",
		"SiteCategorySearchBasic" => "SiteCategorySearchBasic",
		"SiteCategorySearchRowBasic" => "SiteCategorySearchRowBasic",
		"TimeBillSearchBasic" => "TimeBillSearchBasic",
		"TimeBillSearchRowBasic" => "TimeBillSearchRowBasic",
		"SolutionSearchBasic" => "SolutionSearchBasic",
		"SolutionSearchRowBasic" => "SolutionSearchRowBasic",
		"TopicSearchBasic" => "TopicSearchBasic",
		"TopicSearchRowBasic" => "TopicSearchRowBasic",
		"SubsidiarySearchBasic" => "SubsidiarySearchBasic",
		"SubsidiarySearchRowBasic" => "SubsidiarySearchRowBasic",
		"GiftCertificateSearchBasic" => "GiftCertificateSearchBasic",
		"GiftCertificateSearchRowBasic" => "GiftCertificateSearchRowBasic",
		"FolderSearchBasic" => "FolderSearchBasic",
		"FolderSearchRowBasic" => "FolderSearchRowBasic",
		"FileSearchBasic" => "FileSearchBasic",
		"FileSearchRowBasic" => "FileSearchRowBasic",
		"JobSearchBasic" => "JobSearchBasic",
		"JobSearchRowBasic" => "JobSearchRowBasic",
		"IssueSearchBasic" => "IssueSearchBasic",
		"IssueSearchRowBasic" => "IssueSearchRowBasic",
		"GroupMemberSearchBasic" => "GroupMemberSearchBasic",
		"CampaignSearchBasic" => "CampaignSearchBasic",
		"CampaignSearchRowBasic" => "CampaignSearchRowBasic",
		"EntityGroupSearchBasic" => "EntityGroupSearchBasic",
		"EntityGroupSearchRowBasic" => "EntityGroupSearchRowBasic",
		"PromotionCodeSearchBasic" => "PromotionCodeSearchBasic",
		"PromotionCodeSearchRowBasic" => "PromotionCodeSearchRowBasic",
		"BudgetSearchBasic" => "BudgetSearchBasic",
		"BudgetSearchRowBasic" => "BudgetSearchRowBasic",
		"ProjectTaskSearchBasic" => "ProjectTaskSearchBasic",
		"ProjectTaskSearchRowBasic" => "ProjectTaskSearchRowBasic",
		"ProjectTaskAssignmentSearchBasic" => "ProjectTaskAssignmentSearchBasic",
		"ProjectTaskAssignmentSearchRowBasic" => "ProjectTaskAssignmentSearchRowBasic",
		"AccountingPeriodSearchBasic" => "AccountingPeriodSearchBasic",
		"AccountingPeriodSearchRowBasic" => "AccountingPeriodSearchRowBasic",
		"ContactCategorySearchBasic" => "ContactCategorySearchBasic",
		"ContactCategorySearchRowBasic" => "ContactCategorySearchRowBasic",
		"ContactRoleSearchBasic" => "ContactRoleSearchBasic",
		"ContactRoleSearchRowBasic" => "ContactRoleSearchRowBasic",
		"CustomerCategorySearchBasic" => "CustomerCategorySearchBasic",
		"CustomerCategorySearchRowBasic" => "CustomerCategorySearchRowBasic",
		"CustomerStatusSearchBasic" => "CustomerStatusSearchBasic",
		"CustomerStatusSearchRowBasic" => "CustomerStatusSearchRowBasic",
		"ExpenseCategorySearchBasic" => "ExpenseCategorySearchBasic",
		"ExpenseCategorySearchRowBasic" => "ExpenseCategorySearchRowBasic",
		"JobStatusSearchBasic" => "JobStatusSearchBasic",
		"JobStatusSearchRowBasic" => "JobStatusSearchRowBasic",
		"JobTypeSearchBasic" => "JobTypeSearchBasic",
		"JobTypeSearchRowBasic" => "JobTypeSearchRowBasic",
		"NoteTypeSearchBasic" => "NoteTypeSearchBasic",
		"NoteTypeSearchRowBasic" => "NoteTypeSearchRowBasic",
		"PartnerCategorySearchBasic" => "PartnerCategorySearchBasic",
		"PartnerCategorySearchRowBasic" => "PartnerCategorySearchRowBasic",
		"PaymentMethodSearchBasic" => "PaymentMethodSearchBasic",
		"PaymentMethodSearchRowBasic" => "PaymentMethodSearchRowBasic",
		"PriceLevelSearchBasic" => "PriceLevelSearchBasic",
		"PriceLevelSearchRowBasic" => "PriceLevelSearchRowBasic",
		"SalesRoleSearchBasic" => "SalesRoleSearchBasic",
		"SalesRoleSearchRowBasic" => "SalesRoleSearchRowBasic",
		"TermSearchBasic" => "TermSearchBasic",
		"TermSearchRowBasic" => "TermSearchRowBasic",
		"VendorCategorySearchBasic" => "VendorCategorySearchBasic",
		"VendorCategorySearchRowBasic" => "VendorCategorySearchRowBasic",
		"WinLossReasonSearchBasic" => "WinLossReasonSearchBasic",
		"WinLossReasonSearchRowBasic" => "WinLossReasonSearchRowBasic",
		"OriginatingLeadSearchBasic" => "OriginatingLeadSearchBasic",
		"OriginatingLeadSearchRowBasic" => "OriginatingLeadSearchRowBasic",
		"UnitsTypeSearchBasic" => "UnitsTypeSearchBasic",
		"UnitsTypeSearchRowBasic" => "UnitsTypeSearchRowBasic",
		"CustomListSearchBasic" => "CustomListSearchBasic",
		"CustomListSearchRowBasic" => "CustomListSearchRowBasic",
		"PricingGroupSearchBasic" => "PricingGroupSearchBasic",
		"PricingGroupSearchRowBasic" => "PricingGroupSearchRowBasic",
		"InventoryNumberSearchBasic" => "InventoryNumberSearchBasic",
		"InventoryNumberSearchRowBasic" => "InventoryNumberSearchRowBasic",
		"InventoryNumberBinSearchBasic" => "InventoryNumberBinSearchBasic",
		"InventoryNumberBinSearchRowBasic" => "InventoryNumberBinSearchRowBasic",
		"ItemBinNumberSearchBasic" => "ItemBinNumberSearchBasic",
		"ItemBinNumberSearchRowBasic" => "ItemBinNumberSearchRowBasic",
		"PricingSearchBasic" => "PricingSearchBasic",
		"PricingSearchRowBasic" => "PricingSearchRowBasic",
		"NexusSearchBasic" => "NexusSearchBasic",
		"NexusSearchRowBasic" => "NexusSearchRowBasic",
		"OtherNameCategorySearchBasic" => "OtherNameCategorySearchBasic",
		"OtherNameCategorySearchRowBasic" => "OtherNameCategorySearchRowBasic",
		"CustomerMessageSearchBasic" => "CustomerMessageSearchBasic",
		"CustomerMessageSearchRowBasic" => "CustomerMessageSearchRowBasic",
		"ItemDemandPlanSearchBasic" => "ItemDemandPlanSearchBasic",
		"ItemDemandPlanSearchRowBasic" => "ItemDemandPlanSearchRowBasic",
		"ItemSupplyPlanSearchBasic" => "ItemSupplyPlanSearchBasic",
		"ItemSupplyPlanSearchRowBasic" => "ItemSupplyPlanSearchRowBasic",
		"CurrencyRateSearchBasic" => "CurrencyRateSearchBasic",
		"CurrencyRateSearchRowBasic" => "CurrencyRateSearchRowBasic",
		"ItemRevisionSearchBasic" => "ItemRevisionSearchBasic",
		"ItemRevisionSearchRowBasic" => "ItemRevisionSearchRowBasic",
		"CouponCodeSearchBasic" => "CouponCodeSearchBasic",
		"CouponCodeSearchRowBasic" => "CouponCodeSearchRowBasic",
		"PayrollItemSearchBasic" => "PayrollItemSearchBasic",
		"PayrollItemSearchRowBasic" => "PayrollItemSearchRowBasic",
		"ManufacturingCostTemplateSearchBasic" => "ManufacturingCostTemplateSearchBasic",
		"ManufacturingCostTemplateSearchRowBasic" => "ManufacturingCostTemplateSearchRowBasic",
		"ManufacturingRoutingSearchBasic" => "ManufacturingRoutingSearchBasic",
		"ManufacturingRoutingSearchRowBasic" => "ManufacturingRoutingSearchRowBasic",
		"ManufacturingOperationTaskSearchBasic" => "ManufacturingOperationTaskSearchBasic",
		"ManufacturingOperationTaskSearchRowBasic" => "ManufacturingOperationTaskSearchRowBasic",
		"ResourceAllocationSearchBasic" => "ResourceAllocationSearchBasic",
		"ResourceAllocationSearchRowBasic" => "ResourceAllocationSearchRowBasic",
		"CustomSearchJoin" => "CustomSearchJoin",
		"CustomSearchRowBasic" => "CustomSearchRowBasic",
		"ChargeSearchBasic" => "ChargeSearchBasic",
		"ChargeSearchRowBasic" => "ChargeSearchRowBasic",
		"BillingScheduleSearchBasic" => "BillingScheduleSearchBasic",
		"BillingScheduleSearchRowBasic" => "BillingScheduleSearchRowBasic",
		"GlobalAccountMappingSearchBasic" => "GlobalAccountMappingSearchBasic",
		"GlobalAccountMappingSearchRowBasic" => "GlobalAccountMappingSearchRowBasic",
		"ItemAccountMappingSearchBasic" => "ItemAccountMappingSearchBasic",
		"ItemAccountMappingSearchRowBasic" => "ItemAccountMappingSearchRowBasic",
		"TimeEntrySearchBasic" => "TimeEntrySearchBasic",
		"TimeEntrySearchRowBasic" => "TimeEntrySearchRowBasic",
		"TimeSheetSearchBasic" => "TimeSheetSearchBasic",
		"TimeSheetSearchRowBasic" => "TimeSheetSearchRowBasic",
		"AccountingTransactionSearchBasic" => "AccountingTransactionSearchBasic",
		"AccountingTransactionSearchRowBasic" => "AccountingTransactionSearchRowBasic",
		"AddressSearchBasic" => "AddressSearchBasic",
		"AddressSearchRowBasic" => "AddressSearchRowBasic",
		"BillingAccountSearchBasic" => "BillingAccountSearchBasic",
		"BillingAccountSearchRowBasic" => "BillingAccountSearchRowBasic",
		"FairValuePriceSearchBasic" => "FairValuePriceSearchBasic",
		"FairValuePriceSearchRowBasic" => "FairValuePriceSearchRowBasic",
		"UsageSearchBasic" => "UsageSearchBasic",
		"UsageSearchRowBasic" => "UsageSearchRowBasic",
		"CostCategorySearchBasic" => "CostCategorySearchBasic",
		"CostCategorySearchRowBasic" => "CostCategorySearchRowBasic",
		"ConsolidatedExchangeRateSearchBasic" => "ConsolidatedExchangeRateSearchBasic",
		"ConsolidatedExchangeRateSearchRowBasic" => "ConsolidatedExchangeRateSearchRowBasic",
		"TaxDetails" => "TaxDetails",
		"TaxDetailsList" => "TaxDetailsList",
		"TaxDetailSearchBasic" => "TaxDetailSearchBasic",
		"TaxDetailSearchRowBasic" => "TaxDetailSearchRowBasic",
		"TaxGroupSearchBasic" => "TaxGroupSearchBasic",
		"TaxGroupSearchRowBasic" => "TaxGroupSearchRowBasic",
		"SalesTaxItemSearchBasic" => "SalesTaxItemSearchBasic",
		"SalesTaxItemSearchRowBasic" => "SalesTaxItemSearchRowBasic",
		"TaxTypeSearchBasic" => "TaxTypeSearchBasic",
		"TaxTypeSearchRowBasic" => "TaxTypeSearchRowBasic",
		"CalendarEventAccessLevel" => "CalendarEventAccessLevel",
		"CalendarEventAttendeeAttendance" => "CalendarEventAttendeeAttendance",
		"CalendarEventReminderMinutes" => "CalendarEventReminderMinutes",
		"CalendarEventReminderType" => "CalendarEventReminderType",
		"CalendarEventStatus" => "CalendarEventStatus",
		"TaskPriority" => "TaskPriority",
		"TaskReminderMinutes" => "TaskReminderMinutes",
		"TaskReminderType" => "TaskReminderType",
		"TaskStatus" => "TaskStatus",
		"PhoneCallPriority" => "PhoneCallPriority",
		"PhoneCallReminderMinutes" => "PhoneCallReminderMinutes",
		"PhoneCallReminderType" => "PhoneCallReminderType",
		"PhoneCallStatus" => "PhoneCallStatus",
		"ProjectTaskPriority" => "ProjectTaskPriority",
		"ProjectTaskStatus" => "ProjectTaskStatus",
		"ProjectTaskConstraintType" => "ProjectTaskConstraintType",
		"ProjectTaskPredecessorPredecessorType" => "ProjectTaskPredecessorPredecessorType",
		"ResourceAllocationAllocationUnit" => "ResourceAllocationAllocationUnit",
		"ResourceAllocationApprovalStatus" => "ResourceAllocationApprovalStatus",
		"CalendarEvent" => "CalendarEvent",
		"ExclusionDateList" => "ExclusionDateList",
		"CalendarEventAttendee" => "CalendarEventAttendee",
		"CalendarEventAttendeeList" => "CalendarEventAttendeeList",
		"CalendarEventResource" => "CalendarEventResource",
		"CalendarEventResourceList" => "CalendarEventResourceList",
		"CalendarEventSearch" => "CalendarEventSearch",
		"CalendarEventSearchAdvanced" => "CalendarEventSearchAdvanced",
		"CalendarEventSearchRow" => "CalendarEventSearchRow",
		"Task" => "Task",
		"TaskContact" => "TaskContact",
		"TaskContactList" => "TaskContactList",
		"TaskSearch" => "TaskSearch",
		"TaskSearchAdvanced" => "TaskSearchAdvanced",
		"TaskSearchRow" => "TaskSearchRow",
		"PhoneCall" => "PhoneCall",
		"PhoneCallContact" => "PhoneCallContact",
		"PhoneCallContactList" => "PhoneCallContactList",
		"PhoneCallSearch" => "PhoneCallSearch",
		"PhoneCallSearchAdvanced" => "PhoneCallSearchAdvanced",
		"PhoneCallSearchRow" => "PhoneCallSearchRow",
		"ProjectTask" => "ProjectTask",
		"ProjectTaskPredecessor" => "ProjectTaskPredecessor",
		"ProjectTaskPredecessorList" => "ProjectTaskPredecessorList",
		"ProjectTaskAssignee" => "ProjectTaskAssignee",
		"ProjectTaskAssigneeList" => "ProjectTaskAssigneeList",
		"ProjectTaskSearch" => "ProjectTaskSearch",
		"ProjectTaskSearchAdvanced" => "ProjectTaskSearchAdvanced",
		"ProjectTaskSearchRow" => "ProjectTaskSearchRow",
		"PhoneCallTimeItemList" => "PhoneCallTimeItemList",
		"CalendarEventTimeItemList" => "CalendarEventTimeItemList",
		"TaskTimeItemList" => "TaskTimeItemList",
		"ProjectTaskTimeItemList" => "ProjectTaskTimeItemList",
		"ResourceAllocation" => "ResourceAllocation",
		"ResourceAllocationSearch" => "ResourceAllocationSearch",
		"ResourceAllocationSearchAdvanced" => "ResourceAllocationSearchAdvanced",
		"ResourceAllocationSearchRow" => "ResourceAllocationSearchRow",
		"NoteDirection" => "NoteDirection",
		"MessageMessageType" => "MessageMessageType",
		"File" => "File",
		"FileSiteCategory" => "FileSiteCategory",
		"FileSiteCategoryList" => "FileSiteCategoryList",
		"FileSearch" => "FileSearch",
		"FileSearchAdvanced" => "FileSearchAdvanced",
		"FileSearchRow" => "FileSearchRow",
		"Folder" => "Folder",
		"FolderSearch" => "FolderSearch",
		"FolderSearchAdvanced" => "FolderSearchAdvanced",
		"FolderSearchRow" => "FolderSearchRow",
		"Note" => "Note",
		"NoteSearch" => "NoteSearch",
		"NoteSearchAdvanced" => "NoteSearchAdvanced",
		"NoteSearchRow" => "NoteSearchRow",
		"Message" => "Message",
		"MessageMediaItemList" => "MessageMediaItemList",
		"MessageSearch" => "MessageSearch",
		"MessageSearchAdvanced" => "MessageSearchAdvanced",
		"MessageSearchRow" => "MessageSearchRow",
		"EntityType" => "EntityType",
		"CustomerStatusStage" => "CustomerStatusStage",
		"ContactType" => "ContactType",
		"CustomerStage" => "CustomerStage",
		"CustomerCreditHoldOverride" => "CustomerCreditHoldOverride",
		"CustomerMonthlyClosing" => "CustomerMonthlyClosing",
		"EmailPreference" => "EmailPreference",
		"EntityGroupType" => "EntityGroupType",
		"TaxFractionUnit" => "TaxFractionUnit",
		"TaxRounding" => "TaxRounding",
		"JobBillingType" => "JobBillingType",
		"PartnerOtherRelationships" => "PartnerOtherRelationships",
		"CustomerOtherRelationships" => "CustomerOtherRelationships",
		"VendorOtherRelationships" => "VendorOtherRelationships",
		"CustomerNegativeNumberFormat" => "CustomerNegativeNumberFormat",
		"CustomerNumberFormat" => "CustomerNumberFormat",
		"BillingAccountFrequency" => "BillingAccountFrequency",
		"Subscriptions" => "Subscriptions",
		"SubscriptionsList" => "SubscriptionsList",
		"Contact" => "Contact",
		"CategoryList" => "CategoryList",
		"ContactAddressbook" => "ContactAddressbook",
		"ContactAddressbookList" => "ContactAddressbookList",
		"ContactSearch" => "ContactSearch",
		"ContactSearchAdvanced" => "ContactSearchAdvanced",
		"ContactSearchRow" => "ContactSearchRow",
		"Customer" => "Customer",
		"CustomerDownload" => "CustomerDownload",
		"CustomerDownloadList" => "CustomerDownloadList",
		"ContactAccessRoles" => "ContactAccessRoles",
		"ContactAccessRolesList" => "ContactAccessRolesList",
		"CustomerSalesTeamList" => "CustomerSalesTeamList",
		"CustomerAddressbook" => "CustomerAddressbook",
		"CustomerAddressbookList" => "CustomerAddressbookList",
		"CustomerCreditCards" => "CustomerCreditCards",
		"CustomerCreditCardsList" => "CustomerCreditCardsList",
		"CustomerGroupPricing" => "CustomerGroupPricing",
		"CustomerGroupPricingList" => "CustomerGroupPricingList",
		"CustomerItemPricing" => "CustomerItemPricing",
		"CustomerItemPricingList" => "CustomerItemPricingList",
		"CustomerPartnersList" => "CustomerPartnersList",
		"CustomerSearch" => "CustomerSearch",
		"CustomerSearchAdvanced" => "CustomerSearchAdvanced",
		"CustomerSearchRow" => "CustomerSearchRow",
		"CustomerStatus" => "CustomerStatus",
		"Partner" => "Partner",
		"PartnerPromoCode" => "PartnerPromoCode",
		"PartnerPromoCodeList" => "PartnerPromoCodeList",
		"PartnerAddressbook" => "PartnerAddressbook",
		"PartnerAddressbookList" => "PartnerAddressbookList",
		"PartnerSearch" => "PartnerSearch",
		"PartnerSearchAdvanced" => "PartnerSearchAdvanced",
		"PartnerSearchRow" => "PartnerSearchRow",
		"Vendor" => "Vendor",
		"VendorPricingSchedule" => "VendorPricingSchedule",
		"VendorPricingScheduleList" => "VendorPricingScheduleList",
		"VendorAddressbook" => "VendorAddressbook",
		"VendorAddressbookList" => "VendorAddressbookList",
		"VendorRoles" => "VendorRoles",
		"VendorRolesList" => "VendorRolesList",
		"VendorSearch" => "VendorSearch",
		"VendorSearchAdvanced" => "VendorSearchAdvanced",
		"VendorSearchRow" => "VendorSearchRow",
		"EntityGroup" => "EntityGroup",
		"EntityGroupSearch" => "EntityGroupSearch",
		"EntityGroupSearchAdvanced" => "EntityGroupSearchAdvanced",
		"EntityGroupSearchRow" => "EntityGroupSearchRow",
		"Job" => "Job",
		"JobAddressbook" => "JobAddressbook",
		"JobAddressbookList" => "JobAddressbookList",
		"JobResources" => "JobResources",
		"JobResourcesList" => "JobResourcesList",
		"JobMilestones" => "JobMilestones",
		"JobMilestonesList" => "JobMilestonesList",
		"JobCreditCards" => "JobCreditCards",
		"JobCreditCardsList" => "JobCreditCardsList",
		"JobSearch" => "JobSearch",
		"JobSearchAdvanced" => "JobSearchAdvanced",
		"JobSearchRow" => "JobSearchRow",
		"JobType" => "JobType",
		"JobStatus" => "JobStatus",
		"CustomerStatusSearch" => "CustomerStatusSearch",
		"CustomerStatusSearchAdvanced" => "CustomerStatusSearchAdvanced",
		"CustomerStatusSearchRow" => "CustomerStatusSearchRow",
		"JobStatusSearch" => "JobStatusSearch",
		"JobStatusSearchAdvanced" => "JobStatusSearchAdvanced",
		"JobStatusSearchRow" => "JobStatusSearchRow",
		"JobTypeSearch" => "JobTypeSearch",
		"JobTypeSearchAdvanced" => "JobTypeSearchAdvanced",
		"JobTypeSearchRow" => "JobTypeSearchRow",
		"OriginatingLeadSearch" => "OriginatingLeadSearch",
		"OriginatingLeadSearchRow" => "OriginatingLeadSearchRow",
		"CustomerCurrency" => "CustomerCurrency",
		"CustomerCurrencyList" => "CustomerCurrencyList",
		"VendorCurrency" => "VendorCurrency",
		"VendorCurrencyList" => "VendorCurrencyList",
		"JobPlStatement" => "JobPlStatement",
		"JobPlStatementList" => "JobPlStatementList",
		"BillingAccount" => "BillingAccount",
		"BillingAccountSearch" => "BillingAccountSearch",
		"BillingAccountSearchAdvanced" => "BillingAccountSearchAdvanced",
		"BillingAccountSearchRow" => "BillingAccountSearchRow",
		"JobPercentCompleteOverride" => "JobPercentCompleteOverride",
		"JobPercentCompleteOverrideList" => "JobPercentCompleteOverrideList",
		"SupportCaseStatusStage" => "SupportCaseStatusStage",
		"SupportCaseStage" => "SupportCaseStage",
		"SolutionStatus" => "SolutionStatus",
		"IssueEventStatus" => "IssueEventStatus",
		"IssueTrackCode" => "IssueTrackCode",
		"IssueRelationship" => "IssueRelationship",
		"SupportCase" => "SupportCase",
		"EmailEmployeesList" => "EmailEmployeesList",
		"SupportCaseEscalateTo" => "SupportCaseEscalateTo",
		"SupportCaseEscalateToList" => "SupportCaseEscalateToList",
		"SupportCaseSolutions" => "SupportCaseSolutions",
		"SupportCaseSolutionsList" => "SupportCaseSolutionsList",
		"SupportCaseTimeItemList" => "SupportCaseTimeItemList",
		"SupportCaseSearch" => "SupportCaseSearch",
		"SupportCaseSearchAdvanced" => "SupportCaseSearchAdvanced",
		"SupportCaseSearchRow" => "SupportCaseSearchRow",
		"SupportCaseStatus" => "SupportCaseStatus",
		"SupportCaseType" => "SupportCaseType",
		"SupportCaseOrigin" => "SupportCaseOrigin",
		"SupportCaseIssue" => "SupportCaseIssue",
		"SupportCasePriority" => "SupportCasePriority",
		"Solution" => "Solution",
		"SolutionTopics" => "SolutionTopics",
		"SolutionTopicsList" => "SolutionTopicsList",
		"Solutions" => "Solutions",
		"SolutionsList" => "SolutionsList",
		"SolutionSearch" => "SolutionSearch",
		"SolutionSearchAdvanced" => "SolutionSearchAdvanced",
		"SolutionSearchRow" => "SolutionSearchRow",
		"Topic" => "Topic",
		"TopicSolution" => "TopicSolution",
		"TopicSolutionList" => "TopicSolutionList",
		"TopicSearch" => "TopicSearch",
		"TopicSearchAdvanced" => "TopicSearchAdvanced",
		"TopicSearchRow" => "TopicSearchRow",
		"Issue" => "Issue",
		"IssueVersion" => "IssueVersion",
		"IssueVersionList" => "IssueVersionList",
		"IssueSearch" => "IssueSearch",
		"IssueSearchAdvanced" => "IssueSearchAdvanced",
		"IssueSearchRow" => "IssueSearchRow",
		"IssueRelatedIssues" => "IssueRelatedIssues",
		"IssueRelatedIssuesList" => "IssueRelatedIssuesList",
		"CurrencyLocale" => "CurrencyLocale",
		"AccountType" => "AccountType",
		"ItemCostingMethod" => "ItemCostingMethod",
		"ItemProductFeed" => "ItemProductFeed",
		"ItemType" => "ItemType",
		"ItemWeightUnit" => "ItemWeightUnit",
		"ItemPreferenceCriterion" => "ItemPreferenceCriterion",
		"ItemOverallQuantityPricingType" => "ItemOverallQuantityPricingType",
		"ScheduleBCode" => "ScheduleBCode",
		"ItemSubType" => "ItemSubType",
		"CurrencyCurrencyPrecision" => "CurrencyCurrencyPrecision",
		"CurrencyFxRateUpdateTimezone" => "CurrencyFxRateUpdateTimezone",
		"SalesTaxItemAvailable" => "SalesTaxItemAvailable",
		"ItemEbayAuctionDuration" => "ItemEbayAuctionDuration",
		"ItemOutOfStockBehavior" => "ItemOutOfStockBehavior",
		"ItemEbayRelistingOption" => "ItemEbayRelistingOption",
		"ConsolidatedRate" => "ConsolidatedRate",
		"CashFlowRateType" => "CashFlowRateType",
		"GeneralRateType" => "GeneralRateType",
		"ItemMatrixType" => "ItemMatrixType",
		"ItemDemandSource" => "ItemDemandSource",
		"ItemSupplyLotSizingMethod" => "ItemSupplyLotSizingMethod",
		"ItemSupplyType" => "ItemSupplyType",
		"ItemSupplyReplenishmentMethod" => "ItemSupplyReplenishmentMethod",
		"RevRecScheduleRecogIntervalSrc" => "RevRecScheduleRecogIntervalSrc",
		"RevRecScheduleRecurrenceType" => "RevRecScheduleRecurrenceType",
		"RevRecScheduleAmortizationType" => "RevRecScheduleAmortizationType",
		"RevRecScheduleAmortizationStatus" => "RevRecScheduleAmortizationStatus",
		"CostCategoryItemCostType" => "CostCategoryItemCostType",
		"ItemAtpMethod" => "ItemAtpMethod",
		"AssemblyItemEffectiveBomControl" => "AssemblyItemEffectiveBomControl",
		"ItemInvtClassification" => "ItemInvtClassification",
		"PeriodicLotSizeType" => "PeriodicLotSizeType",
		"HazmatPackingGroup" => "HazmatPackingGroup",
		"TaxAcctType" => "TaxAcctType",
		"ItemOverheadType" => "ItemOverheadType",
		"ItemCostAccountingStatus" => "ItemCostAccountingStatus",
		"BillingScheduleRecurrenceRecurrenceUnits" => "BillingScheduleRecurrenceRecurrenceUnits",
		"BillingScheduleType" => "BillingScheduleType",
		"BillingScheduleFrequency" => "BillingScheduleFrequency",
		"ItemAccountMappingItemAccount" => "ItemAccountMappingItemAccount",
		"AccountingBookStatus" => "AccountingBookStatus",
		"BillingScheduleRepeatEvery" => "BillingScheduleRepeatEvery",
		"BillingScheduleMonthDow" => "BillingScheduleMonthDow",
		"BillingScheduleYearMonth" => "BillingScheduleYearMonth",
		"BillingScheduleYearDow" => "BillingScheduleYearDow",
		"BillingScheduleYearDowim" => "BillingScheduleYearDowim",
		"BillingScheduleYearDowimMonth" => "BillingScheduleYearDowimMonth",
		"BillingScheduleMonthDowim" => "BillingScheduleMonthDowim",
		"BillingScheduleRecurrenceMode" => "BillingScheduleRecurrenceMode",
		"InventoryItemFraudRisk" => "InventoryItemFraudRisk",
		"BillingScheduleRecurrencePattern" => "BillingScheduleRecurrencePattern",
		"ItemCreateRevenuePlansOn" => "ItemCreateRevenuePlansOn",
		"LocationTimeZone" => "LocationTimeZone",
		"FairValuePriceFairValueRangePolicy" => "FairValuePriceFairValueRangePolicy",
		"LocationGeolocationMethod" => "LocationGeolocationMethod",
		"LocationAutoAssignmentRegionSetting" => "LocationAutoAssignmentRegionSetting",
		"LocationType" => "LocationType",
		"ClassTranslation" => "ClassTranslation",
		"ClassTranslationList" => "ClassTranslationList",
		"ContactCategory" => "ContactCategory",
		"CustomerCategory" => "CustomerCategory",
		"SalesRole" => "SalesRole",
		"PriceLevel" => "PriceLevel",
		"WinLossReason" => "WinLossReason",
		"Term" => "Term",
		"NoteType" => "NoteType",
		"PaymentMethod" => "PaymentMethod",
		"LeadSource" => "LeadSource",
		"Price" => "Price",
		"PriceList" => "PriceList",
		"Pricing" => "Pricing",
		"PricingMatrix" => "PricingMatrix",
		"Rate" => "Rate",
		"RateList" => "RateList",
		"BillingRates" => "BillingRates",
		"BillingRatesMatrix" => "BillingRatesMatrix",
		"Translation" => "Translation",
		"TranslationList" => "TranslationList",
		"ItemOptionsList" => "ItemOptionsList",
		"ItemVendor" => "ItemVendor",
		"ItemVendorList" => "ItemVendorList",
		"SiteCategory" => "SiteCategory",
		"SiteCategoryList" => "SiteCategoryList",
		"ProductFeedList" => "ProductFeedList",
		"ItemMember" => "ItemMember",
		"ItemMemberList" => "ItemMemberList",
		"InventoryItem" => "InventoryItem",
		"MatrixOptionList" => "MatrixOptionList",
		"InventoryItemBinNumber" => "InventoryItemBinNumber",
		"InventoryItemBinNumberList" => "InventoryItemBinNumberList",
		"InventoryItemLocations" => "InventoryItemLocations",
		"InventoryItemLocationsList" => "InventoryItemLocationsList",
		"PresentationItemList" => "PresentationItemList",
		"DescriptionItem" => "DescriptionItem",
		"DiscountItem" => "DiscountItem",
		"DownloadItem" => "DownloadItem",
		"MarkupItem" => "MarkupItem",
		"PaymentItem" => "PaymentItem",
		"SubtotalItem" => "SubtotalItem",
		"NonInventoryPurchaseItem" => "NonInventoryPurchaseItem",
		"NonInventorySaleItem" => "NonInventorySaleItem",
		"NonInventoryResaleItem" => "NonInventoryResaleItem",
		"OtherChargeResaleItem" => "OtherChargeResaleItem",
		"OtherChargePurchaseItem" => "OtherChargePurchaseItem",
		"ServiceResaleItem" => "ServiceResaleItem",
		"ServicePurchaseItem" => "ServicePurchaseItem",
		"ServiceSaleItem" => "ServiceSaleItem",
		"OtherChargeSaleItem" => "OtherChargeSaleItem",
		"Currency" => "Currency",
		"ExpenseCategory" => "ExpenseCategory",
		"Account" => "Account",
		"AccountSearch" => "AccountSearch",
		"AccountSearchAdvanced" => "AccountSearchAdvanced",
		"AccountSearchRow" => "AccountSearchRow",
		"Department" => "Department",
		"DepartmentSearch" => "DepartmentSearch",
		"DepartmentSearchAdvanced" => "DepartmentSearchAdvanced",
		"DepartmentSearchRow" => "DepartmentSearchRow",
		"Classification" => "Classification",
		"ClassificationSearch" => "ClassificationSearch",
		"ClassificationSearchAdvanced" => "ClassificationSearchAdvanced",
		"ClassificationSearchRow" => "ClassificationSearchRow",
		"Location" => "Location",
		"LocationSearch" => "LocationSearch",
		"LocationSearchAdvanced" => "LocationSearchAdvanced",
		"LocationSearchRow" => "LocationSearchRow",
		"UnitsType" => "UnitsType",
		"UnitsTypeUom" => "UnitsTypeUom",
		"UnitsTypeUomList" => "UnitsTypeUomList",
		"ItemSearch" => "ItemSearch",
		"ItemSearchAdvanced" => "ItemSearchAdvanced",
		"ItemSearchRow" => "ItemSearchRow",
		"ContactRole" => "ContactRole",
		"Bin" => "Bin",
		"BinSearch" => "BinSearch",
		"BinSearchAdvanced" => "BinSearchAdvanced",
		"BinSearchRow" => "BinSearchRow",
		"SalesTaxItem" => "SalesTaxItem",
		"TaxGroup" => "TaxGroup",
		"TaxGroupTaxItem" => "TaxGroupTaxItem",
		"TaxGroupTaxItemList" => "TaxGroupTaxItemList",
		"TaxType" => "TaxType",
		"TaxTypeNexusesTax" => "TaxTypeNexusesTax",
		"TaxTypeNexusesTaxList" => "TaxTypeNexusesTaxList",
		"SerializedInventoryItem" => "SerializedInventoryItem",
		"SerializedInventoryItemLocations" => "SerializedInventoryItemLocations",
		"SerializedInventoryItemLocationsList" => "SerializedInventoryItemLocationsList",
		"SerializedInventoryItemNumbers" => "SerializedInventoryItemNumbers",
		"SerializedInventoryItemNumbersList" => "SerializedInventoryItemNumbersList",
		"LotNumberedInventoryItem" => "LotNumberedInventoryItem",
		"LotNumberedInventoryItemLocations" => "LotNumberedInventoryItemLocations",
		"LotNumberedInventoryItemLocationsList" => "LotNumberedInventoryItemLocationsList",
		"LotNumberedInventoryItemNumbers" => "LotNumberedInventoryItemNumbers",
		"LotNumberedInventoryItemNumbersList" => "LotNumberedInventoryItemNumbersList",
		"GiftCertificateItem" => "GiftCertificateItem",
		"GiftCertificateItemAuthCodes" => "GiftCertificateItemAuthCodes",
		"GiftCertificateItemAuthCodesList" => "GiftCertificateItemAuthCodesList",
		"Subsidiary" => "Subsidiary",
		"SubsidiaryNexus" => "SubsidiaryNexus",
		"SubsidiaryNexusList" => "SubsidiaryNexusList",
		"SubsidiarySearch" => "SubsidiarySearch",
		"SubsidiarySearchAdvanced" => "SubsidiarySearchAdvanced",
		"SubsidiarySearchRow" => "SubsidiarySearchRow",
		"GiftCertificate" => "GiftCertificate",
		"GiftCertificateSearch" => "GiftCertificateSearch",
		"GiftCertificateSearchAdvanced" => "GiftCertificateSearchAdvanced",
		"GiftCertificateSearchRow" => "GiftCertificateSearchRow",
		"PartnerCategory" => "PartnerCategory",
		"VendorCategory" => "VendorCategory",
		"KitItem" => "KitItem",
		"AssemblyItem" => "AssemblyItem",
		"SerializedAssemblyItem" => "SerializedAssemblyItem",
		"LotNumberedAssemblyItem" => "LotNumberedAssemblyItem",
		"ServiceItemTaskTemplates" => "ServiceItemTaskTemplates",
		"ServiceItemTaskTemplatesList" => "ServiceItemTaskTemplatesList",
		"State" => "State",
		"AccountingPeriod" => "AccountingPeriod",
		"BudgetCategory" => "BudgetCategory",
		"AccountingPeriodSearch" => "AccountingPeriodSearch",
		"AccountingPeriodSearchAdvanced" => "AccountingPeriodSearchAdvanced",
		"AccountingPeriodSearchRow" => "AccountingPeriodSearchRow",
		"ContactCategorySearch" => "ContactCategorySearch",
		"ContactCategorySearchAdvanced" => "ContactCategorySearchAdvanced",
		"ContactCategorySearchRow" => "ContactCategorySearchRow",
		"ContactRoleSearch" => "ContactRoleSearch",
		"ContactRoleSearchAdvanced" => "ContactRoleSearchAdvanced",
		"ContactRoleSearchRow" => "ContactRoleSearchRow",
		"CustomerCategorySearch" => "CustomerCategorySearch",
		"CustomerCategorySearchAdvanced" => "CustomerCategorySearchAdvanced",
		"CustomerCategorySearchRow" => "CustomerCategorySearchRow",
		"ExpenseCategorySearch" => "ExpenseCategorySearch",
		"ExpenseCategorySearchAdvanced" => "ExpenseCategorySearchAdvanced",
		"ExpenseCategorySearchRow" => "ExpenseCategorySearchRow",
		"NoteTypeSearch" => "NoteTypeSearch",
		"NoteTypeSearchAdvanced" => "NoteTypeSearchAdvanced",
		"NoteTypeSearchRow" => "NoteTypeSearchRow",
		"PartnerCategorySearch" => "PartnerCategorySearch",
		"PartnerCategorySearchAdvanced" => "PartnerCategorySearchAdvanced",
		"PartnerCategorySearchRow" => "PartnerCategorySearchRow",
		"PaymentMethodSearch" => "PaymentMethodSearch",
		"PaymentMethodSearchAdvanced" => "PaymentMethodSearchAdvanced",
		"PaymentMethodSearchRow" => "PaymentMethodSearchRow",
		"PriceLevelSearch" => "PriceLevelSearch",
		"PriceLevelSearchAdvanced" => "PriceLevelSearchAdvanced",
		"PriceLevelSearchRow" => "PriceLevelSearchRow",
		"SalesRoleSearch" => "SalesRoleSearch",
		"SalesRoleSearchAdvanced" => "SalesRoleSearchAdvanced",
		"SalesRoleSearchRow" => "SalesRoleSearchRow",
		"TermSearch" => "TermSearch",
		"TermSearchAdvanced" => "TermSearchAdvanced",
		"TermSearchRow" => "TermSearchRow",
		"VendorCategorySearch" => "VendorCategorySearch",
		"VendorCategorySearchAdvanced" => "VendorCategorySearchAdvanced",
		"VendorCategorySearchRow" => "VendorCategorySearchRow",
		"WinLossReasonSearch" => "WinLossReasonSearch",
		"WinLossReasonSearchAdvanced" => "WinLossReasonSearchAdvanced",
		"WinLossReasonSearchRow" => "WinLossReasonSearchRow",
		"UnitsTypeSearch" => "UnitsTypeSearch",
		"UnitsTypeSearchAdvanced" => "UnitsTypeSearchAdvanced",
		"UnitsTypeSearchRow" => "UnitsTypeSearchRow",
		"PricingGroup" => "PricingGroup",
		"PricingGroupSearch" => "PricingGroupSearch",
		"PricingGroupSearchAdvanced" => "PricingGroupSearchAdvanced",
		"PricingGroupSearchRow" => "PricingGroupSearchRow",
		"InventoryNumber" => "InventoryNumber",
		"InventoryNumberLocations" => "InventoryNumberLocations",
		"InventoryNumberLocationsList" => "InventoryNumberLocationsList",
		"InventoryNumberSearch" => "InventoryNumberSearch",
		"InventoryNumberSearchAdvanced" => "InventoryNumberSearchAdvanced",
		"InventoryNumberSearchRow" => "InventoryNumberSearchRow",
		"RevRecSchedule" => "RevRecSchedule",
		"RevRecScheduleRecurrence" => "RevRecScheduleRecurrence",
		"RevRecScheduleRecurrenceList" => "RevRecScheduleRecurrenceList",
		"RevRecTemplate" => "RevRecTemplate",
		"RevRecTemplateRecurrence" => "RevRecTemplateRecurrence",
		"RevRecTemplateRecurrenceList" => "RevRecTemplateRecurrenceList",
		"RevRecScheduleSearch" => "RevRecScheduleSearch",
		"RevRecScheduleSearchAdvanced" => "RevRecScheduleSearchAdvanced",
		"RevRecScheduleSearchRow" => "RevRecScheduleSearchRow",
		"RevRecTemplateSearch" => "RevRecTemplateSearch",
		"RevRecTemplateSearchAdvanced" => "RevRecTemplateSearchAdvanced",
		"RevRecTemplateSearchRow" => "RevRecTemplateSearchRow",
		"CostCategory" => "CostCategory",
		"Nexus" => "Nexus",
		"NexusSearch" => "NexusSearch",
		"NexusSearchAdvanced" => "NexusSearchAdvanced",
		"NexusSearchRow" => "NexusSearchRow",
		"CustomerMessage" => "CustomerMessage",
		"OtherNameCategory" => "OtherNameCategory",
		"OtherNameCategorySearch" => "OtherNameCategorySearch",
		"OtherNameCategorySearchAdvanced" => "OtherNameCategorySearchAdvanced",
		"OtherNameCategorySearchRow" => "OtherNameCategorySearchRow",
		"CustomerMessageSearch" => "CustomerMessageSearch",
		"CustomerMessageSearchAdvanced" => "CustomerMessageSearchAdvanced",
		"CustomerMessageSearchRow" => "CustomerMessageSearchRow",
		"ItemGroup" => "ItemGroup",
		"CurrencyRateSearch" => "CurrencyRateSearch",
		"CurrencyRateSearchAdvanced" => "CurrencyRateSearchAdvanced",
		"CurrencyRateSearchRow" => "CurrencyRateSearchRow",
		"ItemRevision" => "ItemRevision",
		"ItemRevisionSearch" => "ItemRevisionSearch",
		"ItemRevisionSearchAdvanced" => "ItemRevisionSearchAdvanced",
		"ItemRevisionSearchRow" => "ItemRevisionSearchRow",
		"AccountingPeriodFiscalCalendars" => "AccountingPeriodFiscalCalendars",
		"AccountingPeriodFiscalCalendarsList" => "AccountingPeriodFiscalCalendarsList",
		"TaxAcct" => "TaxAcct",
		"ExpenseCategoryRates" => "ExpenseCategoryRates",
		"ExpenseCategoryRatesList" => "ExpenseCategoryRatesList",
		"BillingSchedule" => "BillingSchedule",
		"BillingScheduleMilestone" => "BillingScheduleMilestone",
		"BillingScheduleMilestoneList" => "BillingScheduleMilestoneList",
		"BillingScheduleRecurrence" => "BillingScheduleRecurrence",
		"BillingScheduleRecurrenceList" => "BillingScheduleRecurrenceList",
		"BillingScheduleSearch" => "BillingScheduleSearch",
		"BillingScheduleSearchAdvanced" => "BillingScheduleSearchAdvanced",
		"BillingScheduleSearchRow" => "BillingScheduleSearchRow",
		"GlobalAccountMapping" => "GlobalAccountMapping",
		"GlobalAccountMappingSearch" => "GlobalAccountMappingSearch",
		"GlobalAccountMappingSearchAdvanced" => "GlobalAccountMappingSearchAdvanced",
		"GlobalAccountMappingSearchRow" => "GlobalAccountMappingSearchRow",
		"ItemAccountMapping" => "ItemAccountMapping",
		"ItemAccountMappingSearch" => "ItemAccountMappingSearch",
		"ItemAccountMappingSearchAdvanced" => "ItemAccountMappingSearchAdvanced",
		"ItemAccountMappingSearchRow" => "ItemAccountMappingSearchRow",
		"ItemAccountingBookDetail" => "ItemAccountingBookDetail",
		"ItemAccountingBookDetailList" => "ItemAccountingBookDetailList",
		"SubsidiaryAccountingBookDetail" => "SubsidiaryAccountingBookDetail",
		"SubsidiaryAccountingBookDetailList" => "SubsidiaryAccountingBookDetailList",
		"PaymentMethodVisuals" => "PaymentMethodVisuals",
		"PaymentMethodVisualsList" => "PaymentMethodVisualsList",
		"FairValuePrice" => "FairValuePrice",
		"FairValuePriceSearch" => "FairValuePriceSearch",
		"FairValuePriceSearchAdvanced" => "FairValuePriceSearchAdvanced",
		"FairValuePriceSearchRow" => "FairValuePriceSearchRow",
		"LocationRegions" => "LocationRegions",
		"LocationRegionsList" => "LocationRegionsList",
		"TaxTypeNexusAccounts" => "TaxTypeNexusAccounts",
		"TaxTypeNexusAccountsList" => "TaxTypeNexusAccountsList",
		"SubsidiaryTaxRegistration" => "SubsidiaryTaxRegistration",
		"SubsidiaryTaxRegistrationList" => "SubsidiaryTaxRegistrationList",
		"CostCategorySearch" => "CostCategorySearch",
		"CostCategorySearchAdvanced" => "CostCategorySearchAdvanced",
		"CostCategorySearchRow" => "CostCategorySearchRow",
		"AccountLocalizations" => "AccountLocalizations",
		"AccountLocalizationsList" => "AccountLocalizationsList",
		"ConsolidatedExchangeRate" => "ConsolidatedExchangeRate",
		"ConsolidatedExchangeRateSearch" => "ConsolidatedExchangeRateSearch",
		"ConsolidatedExchangeRateSearchAdvanced" => "ConsolidatedExchangeRateSearchAdvanced",
		"ConsolidatedExchangeRateSearchRow" => "ConsolidatedExchangeRateSearchRow",
		"TaxGroupSearch" => "TaxGroupSearch",
		"TaxGroupSearchAdvanced" => "TaxGroupSearchAdvanced",
		"TaxGroupSearchRow" => "TaxGroupSearchRow",
		"SalesTaxItemSearch" => "SalesTaxItemSearch",
		"SalesTaxItemSearchAdvanced" => "SalesTaxItemSearchAdvanced",
		"SalesTaxItemSearchRow" => "SalesTaxItemSearchRow",
		"TaxTypeSearch" => "TaxTypeSearch",
		"TaxTypeSearchAdvanced" => "TaxTypeSearchAdvanced",
		"TaxTypeSearchRow" => "TaxTypeSearchRow",
		"LocationBusinessHours" => "LocationBusinessHours",
		"LocationBusinessHoursList" => "LocationBusinessHoursList",
		"SalesOrderItemCommitInventory" => "SalesOrderItemCommitInventory",
		"SalesOrderItemCreatePo" => "SalesOrderItemCreatePo",
		"SalesOrderOrderStatus" => "SalesOrderOrderStatus",
		"ItemFulfillmentExportTypeUps" => "ItemFulfillmentExportTypeUps",
		"ItemFulfillmentLicenseExceptionUps" => "ItemFulfillmentLicenseExceptionUps",
		"ItemFulfillmentMethodOfTransportUps" => "ItemFulfillmentMethodOfTransportUps",
		"ItemFulfillmentThirdPartyTypeUps" => "ItemFulfillmentThirdPartyTypeUps",
		"ItemFulfillmentPackageUpsCodMethodUps" => "ItemFulfillmentPackageUpsCodMethodUps",
		"ItemFulfillmentPackageUpsDeliveryConfUps" => "ItemFulfillmentPackageUpsDeliveryConfUps",
		"ItemFulfillmentPackageUpsPackagingUps" => "ItemFulfillmentPackageUpsPackagingUps",
		"ItemFulfillmentPackageUspsDeliveryConfUsps" => "ItemFulfillmentPackageUspsDeliveryConfUsps",
		"ItemFulfillmentPackageUspsPackagingUsps" => "ItemFulfillmentPackageUspsPackagingUsps",
		"ItemFulfillmentB13AFilingOptionFedEx" => "ItemFulfillmentB13AFilingOptionFedEx",
		"ItemFulfillmentHomeDeliveryTypeFedEx" => "ItemFulfillmentHomeDeliveryTypeFedEx",
		"ItemFulfillmentThirdPartyTypeFedEx" => "ItemFulfillmentThirdPartyTypeFedEx",
		"ItemFulfillmentPackageFedExAdmPackageTypeFedEx" => "ItemFulfillmentPackageFedExAdmPackageTypeFedEx",
		"ItemFulfillmentPackageFedExCodMethodFedEx" => "ItemFulfillmentPackageFedExCodMethodFedEx",
		"ItemFulfillmentPackageFedExDeliveryConfFedEx" => "ItemFulfillmentPackageFedExDeliveryConfFedEx",
		"ItemFulfillmentPackageFedExPackagingFedEx" => "ItemFulfillmentPackageFedExPackagingFedEx",
		"ItemFulfillmentPackageFedExSignatureOptionsFedEx" => "ItemFulfillmentPackageFedExSignatureOptionsFedEx",
		"ItemFulfillmentTermsOfSaleFedEx" => "ItemFulfillmentTermsOfSaleFedEx",
		"ItemFulfillmentShipStatus" => "ItemFulfillmentShipStatus",
		"OpportunityStatus" => "OpportunityStatus",
		"TransactionType" => "TransactionType",
		"TransactionStatus" => "TransactionStatus",
		"TransactionPaymentEventResult" => "TransactionPaymentEventResult",
		"TransactionPaymentEventType" => "TransactionPaymentEventType",
		"TransactionPaymentEventHoldReason" => "TransactionPaymentEventHoldReason",
		"ItemFulfillmentPackageFedExCodFreightTypeFedEx" => "ItemFulfillmentPackageFedExCodFreightTypeFedEx",
		"TransactionLinkType" => "TransactionLinkType",
		"ForecastType" => "ForecastType",
		"TransactionLineType" => "TransactionLineType",
		"TransactionApprovalStatus" => "TransactionApprovalStatus",
		"ItemFulfillmentPackageFedExPriorityAlertTypeFedEx" => "ItemFulfillmentPackageFedExPriorityAlertTypeFedEx",
		"ItemFulfillmentHazmatTypeFedEx" => "ItemFulfillmentHazmatTypeFedEx",
		"ItemFulfillmentAncillaryEndorsementFedEx" => "ItemFulfillmentAncillaryEndorsementFedEx",
		"ItemFulfillmentAccessibilityTypeFedEx" => "ItemFulfillmentAccessibilityTypeFedEx",
		"TransactionChargeType" => "TransactionChargeType",
		"AccountingTransactionRevCommitStatus" => "AccountingTransactionRevCommitStatus",
		"AccountingTransactionRevenueStatus" => "AccountingTransactionRevenueStatus",
		"SalesOrderItemFulfillmentChoice" => "SalesOrderItemFulfillmentChoice",
		"Opportunity" => "Opportunity",
		"OpportunitySalesTeam" => "OpportunitySalesTeam",
		"OpportunitySalesTeamList" => "OpportunitySalesTeamList",
		"OpportunityItem" => "OpportunityItem",
		"OpportunityItemList" => "OpportunityItemList",
		"OpportunityCompetitors" => "OpportunityCompetitors",
		"OpportunityCompetitorsList" => "OpportunityCompetitorsList",
		"OpportunitySearch" => "OpportunitySearch",
		"OpportunitySearchAdvanced" => "OpportunitySearchAdvanced",
		"OpportunitySearchRow" => "OpportunitySearchRow",
		"OpportunityPartnersList" => "OpportunityPartnersList",
		"SalesOrder" => "SalesOrder",
		"SalesOrderSalesTeam" => "SalesOrderSalesTeam",
		"SalesOrderSalesTeamList" => "SalesOrderSalesTeamList",
		"SalesOrderItem" => "SalesOrderItem",
		"SalesOrderItemList" => "SalesOrderItemList",
		"SalesOrderPartnersList" => "SalesOrderPartnersList",
		"SalesOrderShipGroupList" => "SalesOrderShipGroupList",
		"TransactionSearch" => "TransactionSearch",
		"TransactionSearchAdvanced" => "TransactionSearchAdvanced",
		"TransactionSearchRow" => "TransactionSearchRow",
		"ItemFulfillment" => "ItemFulfillment",
		"ItemFulfillmentItem" => "ItemFulfillmentItem",
		"ItemFulfillmentItemList" => "ItemFulfillmentItemList",
		"ItemFulfillmentPackage" => "ItemFulfillmentPackage",
		"ItemFulfillmentPackageList" => "ItemFulfillmentPackageList",
		"ItemFulfillmentPackageUps" => "ItemFulfillmentPackageUps",
		"ItemFulfillmentPackageUpsList" => "ItemFulfillmentPackageUpsList",
		"ItemFulfillmentPackageUsps" => "ItemFulfillmentPackageUsps",
		"ItemFulfillmentPackageUspsList" => "ItemFulfillmentPackageUspsList",
		"ItemFulfillmentPackageFedEx" => "ItemFulfillmentPackageFedEx",
		"ItemFulfillmentPackageFedExList" => "ItemFulfillmentPackageFedExList",
		"Invoice" => "Invoice",
		"InvoiceSalesTeam" => "InvoiceSalesTeam",
		"InvoiceSalesTeamList" => "InvoiceSalesTeamList",
		"InvoiceItem" => "InvoiceItem",
		"InvoiceItemList" => "InvoiceItemList",
		"InvoiceItemCost" => "InvoiceItemCost",
		"InvoiceItemCostList" => "InvoiceItemCostList",
		"InvoiceExpCost" => "InvoiceExpCost",
		"InvoiceExpCostList" => "InvoiceExpCostList",
		"InvoiceTime" => "InvoiceTime",
		"InvoiceTimeList" => "InvoiceTimeList",
		"InvoicePartnersList" => "InvoicePartnersList",
		"InvoiceShipGroupList" => "InvoiceShipGroupList",
		"CashSale" => "CashSale",
		"CashSaleSalesTeam" => "CashSaleSalesTeam",
		"CashSaleSalesTeamList" => "CashSaleSalesTeamList",
		"CashSaleItem" => "CashSaleItem",
		"CashSaleItemList" => "CashSaleItemList",
		"CashSaleItemCost" => "CashSaleItemCost",
		"CashSaleItemCostList" => "CashSaleItemCostList",
		"CashSaleExpCost" => "CashSaleExpCost",
		"CashSaleExpCostList" => "CashSaleExpCostList",
		"CashSaleTime" => "CashSaleTime",
		"CashSaleTimeList" => "CashSaleTimeList",
		"CashSalePartnersList" => "CashSalePartnersList",
		"CashSaleShipGroupList" => "CashSaleShipGroupList",
		"Estimate" => "Estimate",
		"EstimateItem" => "EstimateItem",
		"EstimateItemList" => "EstimateItemList",
		"EstimateSalesTeam" => "EstimateSalesTeam",
		"EstimateSalesTeamList" => "EstimateSalesTeamList",
		"EstimatePartnersList" => "EstimatePartnersList",
		"EstimateShipGroupList" => "EstimateShipGroupList",
		"GiftCertRedemption" => "GiftCertRedemption",
		"GiftCertRedemptionList" => "GiftCertRedemptionList",
		"TransactionShipGroup" => "TransactionShipGroup",
		"AccountingTransactionSearch" => "AccountingTransactionSearch",
		"AccountingTransactionSearchAdvanced" => "AccountingTransactionSearchAdvanced",
		"AccountingTransactionSearchRow" => "AccountingTransactionSearchRow",
		"Promotions" => "Promotions",
		"PromotionsList" => "PromotionsList",
		"Usage" => "Usage",
		"UsageSearch" => "UsageSearch",
		"UsageSearchAdvanced" => "UsageSearchAdvanced",
		"UsageSearchRow" => "UsageSearchRow",
		"PurchaseOrderOrderStatus" => "PurchaseOrderOrderStatus",
		"TransactionBillVarianceStatus" => "TransactionBillVarianceStatus",
		"VendorReturnAuthorizationOrderStatus" => "VendorReturnAuthorizationOrderStatus",
		"PurchLandedCostList" => "PurchLandedCostList",
		"VendorBill" => "VendorBill",
		"VendorBillExpense" => "VendorBillExpense",
		"VendorBillExpenseList" => "VendorBillExpenseList",
		"VendorBillItem" => "VendorBillItem",
		"VendorBillItemList" => "VendorBillItemList",
		"PurchaseOrder" => "PurchaseOrder",
		"PurchaseOrderExpense" => "PurchaseOrderExpense",
		"PurchaseOrderExpenseList" => "PurchaseOrderExpenseList",
		"PurchaseOrderItem" => "PurchaseOrderItem",
		"PurchaseOrderItemList" => "PurchaseOrderItemList",
		"ItemReceipt" => "ItemReceipt",
		"ItemReceiptItem" => "ItemReceiptItem",
		"ItemReceiptItemList" => "ItemReceiptItemList",
		"ItemReceiptExpense" => "ItemReceiptExpense",
		"ItemReceiptExpenseList" => "ItemReceiptExpenseList",
		"VendorPayment" => "VendorPayment",
		"VendorPaymentApply" => "VendorPaymentApply",
		"VendorPaymentApplyList" => "VendorPaymentApplyList",
		"VendorPaymentCredit" => "VendorPaymentCredit",
		"VendorPaymentCreditList" => "VendorPaymentCreditList",
		"VendorCredit" => "VendorCredit",
		"VendorCreditExpense" => "VendorCreditExpense",
		"VendorCreditExpenseList" => "VendorCreditExpenseList",
		"VendorCreditItem" => "VendorCreditItem",
		"VendorCreditItemList" => "VendorCreditItemList",
		"VendorCreditApply" => "VendorCreditApply",
		"VendorCreditApplyList" => "VendorCreditApplyList",
		"VendorReturnAuthorization" => "VendorReturnAuthorization",
		"VendorReturnAuthorizationExpense" => "VendorReturnAuthorizationExpense",
		"VendorReturnAuthorizationExpenseList" => "VendorReturnAuthorizationExpenseList",
		"VendorReturnAuthorizationItem" => "VendorReturnAuthorizationItem",
		"VendorReturnAuthorizationItemList" => "VendorReturnAuthorizationItemList",
		"PurchaseRequisition" => "PurchaseRequisition",
		"PurchaseRequisitionExpense" => "PurchaseRequisitionExpense",
		"PurchaseRequisitionExpenseList" => "PurchaseRequisitionExpenseList",
		"PurchaseRequisitionItem" => "PurchaseRequisitionItem",
		"PurchaseRequisitionItemList" => "PurchaseRequisitionItemList",
		"ReturnAuthorizationOrderStatus" => "ReturnAuthorizationOrderStatus",
		"ChargeStage" => "ChargeStage",
		"ChargeUse" => "ChargeUse",
		"CashRefund" => "CashRefund",
		"CashRefundItem" => "CashRefundItem",
		"CashRefundItemList" => "CashRefundItemList",
		"CashRefundSalesTeam" => "CashRefundSalesTeam",
		"CashRefundSalesTeamList" => "CashRefundSalesTeamList",
		"CashRefundPartnersList" => "CashRefundPartnersList",
		"CustomerPayment" => "CustomerPayment",
		"CustomerPaymentApply" => "CustomerPaymentApply",
		"CustomerPaymentApplyList" => "CustomerPaymentApplyList",
		"CustomerPaymentCredit" => "CustomerPaymentCredit",
		"CustomerPaymentCreditList" => "CustomerPaymentCreditList",
		"CustomerPaymentDeposit" => "CustomerPaymentDeposit",
		"CustomerPaymentDepositList" => "CustomerPaymentDepositList",
		"ReturnAuthorization" => "ReturnAuthorization",
		"ReturnAuthorizationItem" => "ReturnAuthorizationItem",
		"ReturnAuthorizationItemList" => "ReturnAuthorizationItemList",
		"ReturnAuthorizationSalesTeam" => "ReturnAuthorizationSalesTeam",
		"ReturnAuthorizationSalesTeamList" => "ReturnAuthorizationSalesTeamList",
		"ReturnAuthorizationPartnersList" => "ReturnAuthorizationPartnersList",
		"CreditMemo" => "CreditMemo",
		"CreditMemoSalesTeam" => "CreditMemoSalesTeam",
		"CreditMemoSalesTeamList" => "CreditMemoSalesTeamList",
		"CreditMemoItem" => "CreditMemoItem",
		"CreditMemoItemList" => "CreditMemoItemList",
		"CreditMemoApply" => "CreditMemoApply",
		"CreditMemoApplyList" => "CreditMemoApplyList",
		"CreditMemoPartnersList" => "CreditMemoPartnersList",
		"CustomerRefund" => "CustomerRefund",
		"CustomerRefundApply" => "CustomerRefundApply",
		"CustomerRefundApplyList" => "CustomerRefundApplyList",
		"CustomerRefundDeposit" => "CustomerRefundDeposit",
		"CustomerRefundDepositList" => "CustomerRefundDepositList",
		"CustomerDeposit" => "CustomerDeposit",
		"CustomerDepositApply" => "CustomerDepositApply",
		"CustomerDepositApplyList" => "CustomerDepositApplyList",
		"DepositApplication" => "DepositApplication",
		"DepositApplicationApply" => "DepositApplicationApply",
		"DepositApplicationApplyList" => "DepositApplicationApplyList",
		"Charge" => "Charge",
		"ChargeSearch" => "ChargeSearch",
		"ChargeSearchAdvanced" => "ChargeSearchAdvanced",
		"ChargeSearchRow" => "ChargeSearchRow",
		"BudgetBudgetType" => "BudgetBudgetType",
		"Budget" => "Budget",
		"BudgetSearch" => "BudgetSearch",
		"BudgetSearchAdvanced" => "BudgetSearchAdvanced",
		"BudgetSearchRow" => "BudgetSearchRow",
		"CheckLandedCostList" => "CheckLandedCostList",
		"Check" => "Check",
		"CheckExpense" => "CheckExpense",
		"CheckExpenseList" => "CheckExpenseList",
		"CheckItem" => "CheckItem",
		"CheckItemList" => "CheckItemList",
		"Deposit" => "Deposit",
		"DepositPayment" => "DepositPayment",
		"DepositPaymentList" => "DepositPaymentList",
		"DepositCashBack" => "DepositCashBack",
		"DepositCashBackList" => "DepositCashBackList",
		"DepositOther" => "DepositOther",
		"DepositOtherList" => "DepositOtherList",
		"TransferOrderItemCommitInventory" => "TransferOrderItemCommitInventory",
		"TransferOrderOrderStatus" => "TransferOrderOrderStatus",
		"WorkOrderItemItemCommitInventory" => "WorkOrderItemItemCommitInventory",
		"WorkOrderOrderStatus" => "WorkOrderOrderStatus",
		"WorkOrderSchedulingMethod" => "WorkOrderSchedulingMethod",
		"InventoryAdjustment" => "InventoryAdjustment",
		"InventoryAdjustmentInventory" => "InventoryAdjustmentInventory",
		"InventoryAdjustmentInventoryList" => "InventoryAdjustmentInventoryList",
		"AssemblyBuild" => "AssemblyBuild",
		"AssemblyUnbuild" => "AssemblyUnbuild",
		"AssemblyComponent" => "AssemblyComponent",
		"AssemblyComponentList" => "AssemblyComponentList",
		"TransferOrder" => "TransferOrder",
		"TransferOrderItem" => "TransferOrderItem",
		"TransferOrderItemList" => "TransferOrderItemList",
		"InterCompanyTransferOrder" => "InterCompanyTransferOrder",
		"InterCompanyTransferOrderItem" => "InterCompanyTransferOrderItem",
		"InterCompanyTransferOrderItemList" => "InterCompanyTransferOrderItemList",
		"WorkOrder" => "WorkOrder",
		"WorkOrderItem" => "WorkOrderItem",
		"WorkOrderItemList" => "WorkOrderItemList",
		"SalesTeamList" => "SalesTeamList",
		"PartnersList" => "PartnersList",
		"InventoryTransfer" => "InventoryTransfer",
		"InventoryTransferInventory" => "InventoryTransferInventory",
		"InventoryTransferInventoryList" => "InventoryTransferInventoryList",
		"BinTransfer" => "BinTransfer",
		"BinTransferInventory" => "BinTransferInventory",
		"BinTransferInventoryList" => "BinTransferInventoryList",
		"BinWorksheet" => "BinWorksheet",
		"BinWorksheetItem" => "BinWorksheetItem",
		"BinWorksheetItemList" => "BinWorksheetItemList",
		"WorkOrderIssue" => "WorkOrderIssue",
		"WorkOrderIssueComponent" => "WorkOrderIssueComponent",
		"WorkOrderIssueComponentList" => "WorkOrderIssueComponentList",
		"WorkOrderCompletion" => "WorkOrderCompletion",
		"WorkOrderCompletionComponent" => "WorkOrderCompletionComponent",
		"WorkOrderCompletionComponentList" => "WorkOrderCompletionComponentList",
		"WorkOrderClose" => "WorkOrderClose",
		"WorkOrderCompletionOperation" => "WorkOrderCompletionOperation",
		"WorkOrderCompletionOperationList" => "WorkOrderCompletionOperationList",
		"InventoryCostRevaluation" => "InventoryCostRevaluation",
		"InventoryCostRevaluationCostComponent" => "InventoryCostRevaluationCostComponent",
		"InventoryCostRevaluationCostComponentList" => "InventoryCostRevaluationCostComponentList",
		"JournalEntry" => "JournalEntry",
		"JournalEntryLine" => "JournalEntryLine",
		"JournalEntryLineList" => "JournalEntryLineList",
		"InterCompanyJournalEntry" => "InterCompanyJournalEntry",
		"InterCompanyJournalEntryLine" => "InterCompanyJournalEntryLine",
		"InterCompanyJournalEntryLineList" => "InterCompanyJournalEntryLineList",
		"StatisticalJournalEntry" => "StatisticalJournalEntry",
		"StatisticalJournalEntryLine" => "StatisticalJournalEntryLine",
		"StatisticalJournalEntryLineList" => "StatisticalJournalEntryLineList",
		"InterCompanyJournalEntryAccountingBookDetail" => "InterCompanyJournalEntryAccountingBookDetail",
		"InterCompanyJournalEntryAccountingBookDetailList" => "InterCompanyJournalEntryAccountingBookDetailList",
		"CustomizationFieldType" => "CustomizationFieldType",
		"CustomizationDynamicDefault" => "CustomizationDynamicDefault",
		"CustomizationDisplayType" => "CustomizationDisplayType",
		"CustomizationFilterCompareType" => "CustomizationFilterCompareType",
		"CustomRecordTypePermissionsPermittedLevel" => "CustomRecordTypePermissionsPermittedLevel",
		"CustomRecordTypePermissionsRestriction" => "CustomRecordTypePermissionsRestriction",
		"ItemCustomFieldItemSubType" => "ItemCustomFieldItemSubType",
		"CustomizationAccessLevel" => "CustomizationAccessLevel",
		"CustomizationSearchLevel" => "CustomizationSearchLevel",
		"CustomRecordTypeAccessType" => "CustomRecordTypeAccessType",
		"CustomRecord" => "CustomRecord",
		"CustomRecordSearch" => "CustomRecordSearch",
		"CustomRecordSearchAdvanced" => "CustomRecordSearchAdvanced",
		"CustomRecordSearchRow" => "CustomRecordSearchRow",
		"CustomList" => "CustomList",
		"CustomListCustomValue" => "CustomListCustomValue",
		"CustomListCustomValueList" => "CustomListCustomValueList",
		"CustomListTranslations" => "CustomListTranslations",
		"CustomListTranslationsList" => "CustomListTranslationsList",
		"CustomRecordType" => "CustomRecordType",
		"CustomRecordTypeFieldList" => "CustomRecordTypeFieldList",
		"CustomRecordTypeTabs" => "CustomRecordTypeTabs",
		"CustomRecordTypeTabsList" => "CustomRecordTypeTabsList",
		"CustomRecordTypeForms" => "CustomRecordTypeForms",
		"CustomRecordTypeFormsList" => "CustomRecordTypeFormsList",
		"CustomRecordTypeOnlineForms" => "CustomRecordTypeOnlineForms",
		"CustomRecordTypeOnlineFormsList" => "CustomRecordTypeOnlineFormsList",
		"CustomRecordTypePermissions" => "CustomRecordTypePermissions",
		"CustomRecordTypePermissionsList" => "CustomRecordTypePermissionsList",
		"CustomRecordTypeLinks" => "CustomRecordTypeLinks",
		"CustomRecordTypeLinksList" => "CustomRecordTypeLinksList",
		"CustomRecordTypeManagers" => "CustomRecordTypeManagers",
		"CustomRecordTypeManagersList" => "CustomRecordTypeManagersList",
		"CustomRecordTypeChildren" => "CustomRecordTypeChildren",
		"CustomRecordTypeChildrenList" => "CustomRecordTypeChildrenList",
		"CustomRecordTypeParents" => "CustomRecordTypeParents",
		"CustomRecordTypeParentsList" => "CustomRecordTypeParentsList",
		"CustomRecordTypeTranslations" => "CustomRecordTypeTranslations",
		"CustomRecordTypeTranslationsList" => "CustomRecordTypeTranslationsList",
		"CustomRecordTypeSublists" => "CustomRecordTypeSublists",
		"CustomRecordTypeSublistsList" => "CustomRecordTypeSublistsList",
		"CustomFieldType" => "CustomFieldType",
		"EntityCustomField" => "EntityCustomField",
		"EntityCustomFieldFilter" => "EntityCustomFieldFilter",
		"EntityCustomFieldFilterList" => "EntityCustomFieldFilterList",
		"FldFilterSelList" => "FldFilterSelList",
		"CrmCustomField" => "CrmCustomField",
		"CrmCustomFieldFilter" => "CrmCustomFieldFilter",
		"CrmCustomFieldFilterList" => "CrmCustomFieldFilterList",
		"OtherCustomField" => "OtherCustomField",
		"OtherCustomFieldFilter" => "OtherCustomFieldFilter",
		"OtherCustomFieldFilterList" => "OtherCustomFieldFilterList",
		"ItemCustomField" => "ItemCustomField",
		"ItemCustomFieldFilter" => "ItemCustomFieldFilter",
		"ItemCustomFieldFilterList" => "ItemCustomFieldFilterList",
		"TransactionBodyCustomField" => "TransactionBodyCustomField",
		"TransactionBodyCustomFieldFilter" => "TransactionBodyCustomFieldFilter",
		"TransactionBodyCustomFieldFilterList" => "TransactionBodyCustomFieldFilterList",
		"TransactionColumnCustomField" => "TransactionColumnCustomField",
		"TransactionColumnCustomFieldFilter" => "TransactionColumnCustomFieldFilter",
		"TransactionColumnCustomFieldFilterList" => "TransactionColumnCustomFieldFilterList",
		"ItemOptionCustomField" => "ItemOptionCustomField",
		"ItemsList" => "ItemsList",
		"ItemOptionCustomFieldFilter" => "ItemOptionCustomFieldFilter",
		"ItemOptionCustomFieldFilterList" => "ItemOptionCustomFieldFilterList",
		"CustomRecordCustomField" => "CustomRecordCustomField",
		"CustomRecordCustomFieldFilter" => "CustomRecordCustomFieldFilter",
		"CustomRecordCustomFieldFilterList" => "CustomRecordCustomFieldFilterList",
		"CustomFieldRoleAccess" => "CustomFieldRoleAccess",
		"CustomFieldRoleAccessList" => "CustomFieldRoleAccessList",
		"CustomFieldDepartmentAccess" => "CustomFieldDepartmentAccess",
		"CustomFieldDepartmentAccessList" => "CustomFieldDepartmentAccessList",
		"CustomFieldSubAccess" => "CustomFieldSubAccess",
		"CustomFieldSubAccessList" => "CustomFieldSubAccessList",
		"LanguageValue" => "LanguageValue",
		"LanguageValueList" => "LanguageValueList",
		"CustomFieldTranslations" => "CustomFieldTranslations",
		"CustomFieldTranslationsList" => "CustomFieldTranslationsList",
		"ItemNumberCustomField" => "ItemNumberCustomField",
		"ItemNumberCustomFieldFilter" => "ItemNumberCustomFieldFilter",
		"ItemNumberCustomFieldFilterList" => "ItemNumberCustomFieldFilterList",
		"CustomListSearch" => "CustomListSearch",
		"CustomListSearchAdvanced" => "CustomListSearchAdvanced",
		"CustomListSearchRow" => "CustomListSearchRow",
		"CustomRecordTranslations" => "CustomRecordTranslations",
		"CustomRecordTranslationsList" => "CustomRecordTranslationsList",
		"CustomTransaction" => "CustomTransaction",
		"CustomTransactionLine" => "CustomTransactionLine",
		"CustomTransactionLineList" => "CustomTransactionLineList",
		"EmployeePayFrequency" => "EmployeePayFrequency",
		"EmployeeUseTimeData" => "EmployeeUseTimeData",
		"EmployeeCommissionPaymentPreference" => "EmployeeCommissionPaymentPreference",
		"Gender" => "Gender",
		"EmployeeAccruedTimeAccrualMethod" => "EmployeeAccruedTimeAccrualMethod",
		"EmployeeDirectDepositAccountStatus" => "EmployeeDirectDepositAccountStatus",
		"PayrollItemItemTypeNoHierarchy" => "PayrollItemItemTypeNoHierarchy",
		"EmployeeWorkAssignment" => "EmployeeWorkAssignment",
		"Employee" => "Employee",
		"EmployeeSubscriptions" => "EmployeeSubscriptions",
		"EmployeeSubscriptionsList" => "EmployeeSubscriptionsList",
		"EmployeeAddressbook" => "EmployeeAddressbook",
		"EmployeeAddressbookList" => "EmployeeAddressbookList",
		"EmployeeRoles" => "EmployeeRoles",
		"EmployeeRolesList" => "EmployeeRolesList",
		"EmployeeSearch" => "EmployeeSearch",
		"EmployeeSearchAdvanced" => "EmployeeSearchAdvanced",
		"EmployeeSearchRow" => "EmployeeSearchRow",
		"EmployeeEmergencyContact" => "EmployeeEmergencyContact",
		"EmployeeEmergencyContactList" => "EmployeeEmergencyContactList",
		"EmployeeHrEducation" => "EmployeeHrEducation",
		"EmployeeHrEducationList" => "EmployeeHrEducationList",
		"EmployeeAccruedTime" => "EmployeeAccruedTime",
		"EmployeeAccruedTimeList" => "EmployeeAccruedTimeList",
		"EmployeeDeduction" => "EmployeeDeduction",
		"EmployeeDeductionList" => "EmployeeDeductionList",
		"EmployeeCompanyContribution" => "EmployeeCompanyContribution",
		"EmployeeCompanyContributionList" => "EmployeeCompanyContributionList",
		"EmployeeEarning" => "EmployeeEarning",
		"EmployeeEarningList" => "EmployeeEarningList",
		"EmployeeDirectDeposit" => "EmployeeDirectDeposit",
		"EmployeeDirectDepositList" => "EmployeeDirectDepositList",
		"PayrollItem" => "PayrollItem",
		"PayrollItemSearch" => "PayrollItemSearch",
		"PayrollItemSearchAdvanced" => "PayrollItemSearchAdvanced",
		"PayrollItemSearchRow" => "PayrollItemSearchRow",
		"EmployeeRates" => "EmployeeRates",
		"EmployeeRatesList" => "EmployeeRatesList",
		"EmployeeHcmPosition" => "EmployeeHcmPosition",
		"EmployeeHcmPositionList" => "EmployeeHcmPositionList",
		"MediaType" => "MediaType",
		"FileAttachFrom" => "FileAttachFrom",
		"FileEncoding" => "FileEncoding",
		"TextFileEncoding" => "TextFileEncoding",
		"FolderFolderType" => "FolderFolderType",
		"SiteCategoryTranslation" => "SiteCategoryTranslation",
		"SiteCategoryTranslationList" => "SiteCategoryTranslationList",
		"SiteCategoryPresentationItemList" => "SiteCategoryPresentationItemList",
		"SiteCategorySearch" => "SiteCategorySearch",
		"SiteCategorySearchAdvanced" => "SiteCategorySearchAdvanced",
		"SiteCategorySearchRow" => "SiteCategorySearchRow",
		"TimeBillTimeType" => "TimeBillTimeType",
		"TimeBill" => "TimeBill",
		"TimeBillSearch" => "TimeBillSearch",
		"TimeBillSearchAdvanced" => "TimeBillSearchAdvanced",
		"TimeBillSearchRow" => "TimeBillSearchRow",
		"ExpenseReport" => "ExpenseReport",
		"ExpenseReportExpense" => "ExpenseReportExpense",
		"ExpenseReportExpenseList" => "ExpenseReportExpenseList",
		"PaycheckJournal" => "PaycheckJournal",
		"PaycheckJournalCompanyTax" => "PaycheckJournalCompanyTax",
		"PaycheckJournalCompanyTaxList" => "PaycheckJournalCompanyTaxList",
		"PaycheckJournalDeduction" => "PaycheckJournalDeduction",
		"PaycheckJournalDeductionList" => "PaycheckJournalDeductionList",
		"PaycheckJournalCompanyContribution" => "PaycheckJournalCompanyContribution",
		"PaycheckJournalCompanyContributionList" => "PaycheckJournalCompanyContributionList",
		"PaycheckJournalEarning" => "PaycheckJournalEarning",
		"PaycheckJournalEarningList" => "PaycheckJournalEarningList",
		"PaycheckJournalEmployeeTax" => "PaycheckJournalEmployeeTax",
		"PaycheckJournalEmployeeTaxList" => "PaycheckJournalEmployeeTaxList",
		"TimeEntry" => "TimeEntry",
		"TimeSheet" => "TimeSheet",
		"TimeSheetTimeGrid" => "TimeSheetTimeGrid",
		"TimeSheetTimeGridList" => "TimeSheetTimeGridList",
		"TimeEntrySearch" => "TimeEntrySearch",
		"TimeEntrySearchAdvanced" => "TimeEntrySearchAdvanced",
		"TimeEntrySearchRow" => "TimeEntrySearchRow",
		"TimeSheetSearch" => "TimeSheetSearch",
		"TimeSheetSearchAdvanced" => "TimeSheetSearchAdvanced",
		"TimeSheetSearchRow" => "TimeSheetSearchRow",
		"CampaignCampaignDirectMailStatus" => "CampaignCampaignDirectMailStatus",
		"CampaignCampaignEmailStatus" => "CampaignCampaignEmailStatus",
		"CampaignCampaignEventStatus" => "CampaignCampaignEventStatus",
		"CampaignChannelEventType" => "CampaignChannelEventType",
		"CampaignResponseResponse" => "CampaignResponseResponse",
		"CampaignCampaignEventType" => "CampaignCampaignEventType",
		"CampaignResponse" => "CampaignResponse",
		"CampaignStatus" => "CampaignStatus",
		"PromotionCodeApplyDiscountTo" => "PromotionCodeApplyDiscountTo",
		"CampaignResponseCategory" => "CampaignResponseCategory",
		"PromotionCodeUseType" => "PromotionCodeUseType",
		"Campaign" => "Campaign",
		"CampaignEmail" => "CampaignEmail",
		"CampaignEmailList" => "CampaignEmailList",
		"CampaignDirectMail" => "CampaignDirectMail",
		"CampaignDirectMailList" => "CampaignDirectMailList",
		"CampaignEvent" => "CampaignEvent",
		"CampaignEventList" => "CampaignEventList",
		"CampaignEventResponse" => "CampaignEventResponse",
		"CampaignEventResponseList" => "CampaignEventResponseList",
		"CampaignSearch" => "CampaignSearch",
		"CampaignSearchAdvanced" => "CampaignSearchAdvanced",
		"CampaignSearchRow" => "CampaignSearchRow",
		"CampaignCategory" => "CampaignCategory",
		"CampaignAudience" => "CampaignAudience",
		"CampaignFamily" => "CampaignFamily",
		"CampaignSearchEngine" => "CampaignSearchEngine",
		"CampaignChannel" => "CampaignChannel",
		"CampaignOffer" => "CampaignOffer",
		"CampaignResponseResponses" => "CampaignResponseResponses",
		"CampaignResponseResponsesList" => "CampaignResponseResponsesList",
		"CampaignVertical" => "CampaignVertical",
		"CampaignSubscription" => "CampaignSubscription",
		"PromotionCode" => "PromotionCode",
		"PromotionCodePartners" => "PromotionCodePartners",
		"PromotionCodePartnersList" => "PromotionCodePartnersList",
		"PromotionCodeItems" => "PromotionCodeItems",
		"PromotionCodeItemsList" => "PromotionCodeItemsList",
		"PromotionCodeSearch" => "PromotionCodeSearch",
		"PromotionCodeSearchAdvanced" => "PromotionCodeSearchAdvanced",
		"PromotionCodeSearchRow" => "PromotionCodeSearchRow",
		"PromotionCodeCurrency" => "PromotionCodeCurrency",
		"PromotionCodeCurrencyList" => "PromotionCodeCurrencyList",
		"CouponCode" => "CouponCode",
		"CouponCodeSearch" => "CouponCodeSearch",
		"CouponCodeSearchAdvanced" => "CouponCodeSearchAdvanced",
		"CouponCodeSearchRow" => "CouponCodeSearchRow",
		"DemandPlanCalendarType" => "DemandPlanCalendarType",
		"DemandPlanMonth" => "DemandPlanMonth",
		"DayOfTheWeek" => "DayOfTheWeek",
		"ItemDemandPlanProjectionMethod" => "ItemDemandPlanProjectionMethod",
		"ItemSupplyPlanOrderType" => "ItemSupplyPlanOrderType",
		"ItemDemandPlan" => "ItemDemandPlan",
		"DemandPlan" => "DemandPlan",
		"DemandPlanMatrix" => "DemandPlanMatrix",
		"PeriodDemandPlanList" => "PeriodDemandPlanList",
		"PeriodDemandPlan" => "PeriodDemandPlan",
		"ItemDemandPlanSearch" => "ItemDemandPlanSearch",
		"ItemDemandPlanSearchAdvanced" => "ItemDemandPlanSearchAdvanced",
		"ItemDemandPlanSearchRow" => "ItemDemandPlanSearchRow",
		"ItemSupplyPlan" => "ItemSupplyPlan",
		"ItemSupplyPlanOrder" => "ItemSupplyPlanOrder",
		"ItemSupplyPlanOrderList" => "ItemSupplyPlanOrderList",
		"ItemSupplyPlanSearch" => "ItemSupplyPlanSearch",
		"ItemSupplyPlanSearchAdvanced" => "ItemSupplyPlanSearchAdvanced",
		"ItemSupplyPlanSearchRow" => "ItemSupplyPlanSearchRow",
		"ManufacturingOperationTaskStatus" => "ManufacturingOperationTaskStatus",
		"ManufacturingOperationTaskPredecessorPredecessorType" => "ManufacturingOperationTaskPredecessorPredecessorType",
		"ManufacturingLagType" => "ManufacturingLagType",
		"ManufacturingCostTemplate" => "ManufacturingCostTemplate",
		"ManufacturingCostDetail" => "ManufacturingCostDetail",
		"ManufacturingCostDetailList" => "ManufacturingCostDetailList",
		"ManufacturingCostTemplateSearch" => "ManufacturingCostTemplateSearch",
		"ManufacturingCostTemplateSearchAdvanced" => "ManufacturingCostTemplateSearchAdvanced",
		"ManufacturingCostTemplateSearchRow" => "ManufacturingCostTemplateSearchRow",
		"ManufacturingRouting" => "ManufacturingRouting",
		"ManufacturingRoutingRoutingStep" => "ManufacturingRoutingRoutingStep",
		"ManufacturingRoutingRoutingStepList" => "ManufacturingRoutingRoutingStepList",
		"ManufacturingRoutingSearch" => "ManufacturingRoutingSearch",
		"ManufacturingRoutingSearchAdvanced" => "ManufacturingRoutingSearchAdvanced",
		"ManufacturingRoutingSearchRow" => "ManufacturingRoutingSearchRow",
		"ManufacturingOperationTask" => "ManufacturingOperationTask",
		"ManufacturingOperationTaskSearch" => "ManufacturingOperationTaskSearch",
		"ManufacturingOperationTaskSearchAdvanced" => "ManufacturingOperationTaskSearchAdvanced",
		"ManufacturingOperationTaskSearchRow" => "ManufacturingOperationTaskSearchRow",
		"ManufacturingOperationTaskPredecessor" => "ManufacturingOperationTaskPredecessor",
		"ManufacturingOperationTaskPredecessorList" => "ManufacturingOperationTaskPredecessorList",
		"ManufacturingRoutingRoutingComponent" => "ManufacturingRoutingRoutingComponent",
		"ManufacturingRoutingRoutingComponentList" => "ManufacturingRoutingRoutingComponentList",
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
