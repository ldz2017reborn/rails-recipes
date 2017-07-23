class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  def display_name
    self.email.split("@").first
  end

  has_many :memberships
  has_many :groups, :through => :memberships
  has_one :profile
  has_many :registrations

  accepts_nested_attributes_for :profile

  ROLES = ["admin", "editor"]

  def is_admin?
    self.role == "admin"
  end

  def is_editor?
    ["admin", "editor"].include?(self.role) # 如果是admin 的话当然也有editor 的权限
  end
end
