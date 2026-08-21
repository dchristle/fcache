subroutine increment(value)
  implicit none
  integer, intent(inout) :: value
  value = value + 1
end subroutine increment
