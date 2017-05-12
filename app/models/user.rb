class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  before_create :generate_channel_key

  private

  def generate_channel_key
    begin
      key = SecureRandom.urlsafe_base64
    end while User.where(channel_key: key).exists?
    self.channel_key = key
  end
end
