package peering

import (
	"math"
	"time"
)

var (

	// define the types of delays in string
	PositiveDelayType           string = "Positive"
	NegativeWithHopeDelayType   string = "NegativeWithHope"
	NegativeWithNoHopeDelayType string = "NegativeWithNoHope"
	ZeroDelayType               string = "Zero"
	Minus1DelayType             string = "Minus1"

	MaxDelayTime time.Duration = time.Duration(math.Pow(2, 11) * float64(time.Minute))

	// define the initial delay we apply in each of the types
	InitialDelayTime = map[string]time.Duration{
		PositiveDelayType:           128 * time.Minute,
		NegativeWithHopeDelayType:   2 * time.Minute,
		NegativeWithNoHopeDelayType: 256 * time.Minute,
		ZeroDelayType:               0 * time.Hour,
		Minus1DelayType:             -1000 * time.Hour,
	}
)

/* Basic Structs */
// the interface  to use and defines which methods should be implemented
type DelayObject interface {
	CalculateDelay() time.Duration
	AddDegree()
	GetType() string
	SetDegree(int)
	GetDegree() int
}

// all of our delay types will include this base, as they all have the same data
// just the delay calculation is different
type BaseDelay struct {
	DelayDegree int    // number of times we have delayed
	Type        string // type of delay we apply (positive, negativewithhope...)
}

// NewBaseDelay
// * Constructor
// * we use pointers so the methods are directly added to inherited structs
// @param inputType: the type of delay we want to set (just string)
func NewBaseDelay(inputType string) *BaseDelay {
	return &BaseDelay{
		DelayDegree: 0,
		Type:        inputType,
	}
}

// AddDegree
// * This method will add 1 to the delaydegree
func (bd *BaseDelay) AddDegree() {

	bd.DelayDegree++

}

// SetDegree
// * This method will the delaydegree
func (bd *BaseDelay) SetDegree(newDegree int) {
	bd.DelayDegree = newDegree
}

// GetDegree
// @return the delaydegree
func (bd *BaseDelay) GetDegree() int {

	return bd.DelayDegree

}

// GetType
//@return the type in string format
func (bd BaseDelay) GetType() string {
	return bd.Type
}

/* Specific Structs*/

type PositiveDelay struct {
	*BaseDelay // include it as pointer to have the methods added directly
}

// NewPositiveDelay
// * Constructor
// @return a PositiveDelay object
func NewPositiveDelay() PositiveDelay {
	return PositiveDelay{
		BaseDelay: NewBaseDelay(PositiveDelayType),
	}
}

// CalculateDelay
// * This method will calculate the delay to be applied based on degree
// @return the delay in Time.Duration format
func (d PositiveDelay) CalculateDelay() time.Duration {
	// return 6 hours * the degree (6,12,18...)
	return time.Duration(d.DelayDegree) * InitialDelayTime[d.Type]
}

/**/

type ZeroDelay struct {
	*BaseDelay
}

func NewZeroDelay() ZeroDelay {
	return ZeroDelay{
		BaseDelay: NewBaseDelay(ZeroDelayType),
	}
}

// CalculateDelay
// * This method will calculate the delay to be applied based on degree
// @return the delay in Time.Duration format
func (d ZeroDelay) CalculateDelay() time.Duration {

	// always return 0
	return InitialDelayTime[d.Type]
}

/**/

type Minus1Delay struct {
	*BaseDelay
}

func NewMinus1Delay() Minus1Delay {
	return Minus1Delay{
		BaseDelay: NewBaseDelay(Minus1DelayType),
	}
}

// CalculateDelay
// * This method will calculate the delay to be applied based on degree
// @return the delay in Time.Duration format
func (d Minus1Delay) CalculateDelay() time.Duration {

	// always return a negative delay
	return InitialDelayTime[d.Type]
}

/**/

type NegativeDelay struct {
	*BaseDelay
}

func NewNegativeDelay(inputType string) *NegativeDelay {
	return &NegativeDelay{
		BaseDelay: NewBaseDelay(inputType),
	}
}

// CalculateDelay
// * This method will calculate the delay to be applied based on degree
// @return the delay in Time.Duration format
func (d NegativeDelay) CalculateDelay() time.Duration {

	// if there are no attempts, there is no delay
	if d.DelayDegree == 0 {
		return time.Duration(0)
	}
	// return (2 ** (delaydegree-1)) * 2 minutes (2,4,8,16,32...)
	return time.Duration(math.Pow(2, float64(d.DelayDegree-1))) * InitialDelayTime[d.Type]
}

type NegativeWithHopeDelay struct {
	*NegativeDelay
}

func NewNegativeWithHopeDelay() NegativeWithHopeDelay {
	return NegativeWithHopeDelay{
		NegativeDelay: NewNegativeDelay(NegativeWithHopeDelayType),
	}
}

type NegativeWithNoHopeDelay struct {
	*NegativeDelay
}

func NewNegativeWithNoHopeDelay() NegativeWithNoHopeDelay {
	return NegativeWithNoHopeDelay{
		NegativeDelay: NewNegativeDelay(NegativeWithNoHopeDelayType),
	}
}

func ReturnAccordingDelayObject(delayType string) DelayObject {
	switch delayType {
	case PositiveDelayType:
		return NewPositiveDelay()
	case NegativeWithHopeDelayType:
		return NewNegativeWithHopeDelay()
	case NegativeWithNoHopeDelayType:
		return NewNegativeWithNoHopeDelay()
	case ZeroDelayType:
		return NewZeroDelay()
	case Minus1DelayType:
		return NewMinus1Delay()
	default:
		return NewNegativeWithHopeDelay()
	}
}
