package exceptions

import (
	exceptions "github.com/CodeClarityCE/utility-types/exceptions"
)

const (
	GENERIC_ERROR                        exceptions.ERROR_TYPE = "GenericException"
	PREVIOUS_STAGE_FAILED                exceptions.ERROR_TYPE = "PreviousStageFailed"
	FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT exceptions.ERROR_TYPE = "FailedToReadPreviousStageOutput"
	UNSUPPORTED_LANGUAGE_REQUESTED       exceptions.ERROR_TYPE = "UnsupportedLanguageRequested"
)
