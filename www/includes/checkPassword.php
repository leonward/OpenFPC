<?php
class Ps2_CheckPassword{
  protected $_password;
  protected $_minimumChars;
  protected $_mixedCase = false;
  protected $_minimumNumbers = 0;
  protected $_minimumSymbols = 0;
  protected $_errors = array();

  public function __construct($password, $minimumChars = 8) {
	$this->_password = $password;
	$this->_minimumChars = $minimumChars;
  }

  public function requireMixedCase() {
	$this->_mixedCase = true;
  }
  
  public function requireNumbers($num =1) {
	if (is_numeric($num) && $num > 0) {
	  $this->_minimumNumbers = (int) $num; 
	}
  }
  
  public function requireSymbols($num = 1) {
	if (is_numeric($num) && $num > 0) {
	  $this->_minimumSymbols = (int) $num; 
	}
  }

  public function check() {
    if (preg_match('/\s/', $this->_password)) {
      $this->_errors[] = 'Password cannot contain spaces.';	
    }
    if (strlen($this->_password) < $this->_minimumChars) {
	  $this->_errors[] = "Password must be at least $this->_minimumChars characters.";
    } 
	if ($this->_mixedCase) {
	  $pattern = '/(?=.*[a-z])(?=.*[A-Z])/';
	  if (!preg_match($pattern, $this->_password)) {
		$this->_errors[] = 'Password must include uppercase and lowercase characters.';
	  }
	}
	if ($this->_minimumNumbers) {
	  $pattern = '/\d/';
	  $found = preg_match_all($pattern, $this->_password, $matches);
	  if ($found < $this->_minimumNumbers) {
		$this->_errors[] = "Password must include at least $this->_minimumNumbers number(s).";
	  }
	}
	if ($this->_minimumSymbols) {
	  $pattern = "/[-!$%^&*(){}<>[\]'" . '"|#@:;.,?+=_\/\~]/';
	  $found = preg_match_all($pattern, $this->_password, $matches);
	  if ($found < $this->_minimumSymbols) {
		$this->_errors[] = "Password must include at least $this->_minimumSymbols nonalphanumeric character(s)."; 
	  }
	}
	return $this->_errors ? false : true;
  }

  public function getErrors() {
	return $this->_errors; 
  }
}
