module implementation_module
  implicit none
contains
  integer function computed_value(input)
    integer, intent(in) :: input
    computed_value = input + 1
  end function computed_value
end module implementation_module
