class RelationshipsController < ApplicationController
  before_action :logged_in_user
  before_action :load_user, only: [:create]
  before_action :load_relationship, only: [:destroy]

   def create
    current_user.follow @user
    respond_to do |format|
      format.html { redirect_to @user }
      format.js
    end
  end

  def destroy
    current_user.unfollow @user
    respond_to do |format|
      format.html { redirect_to @user }
      format.js
    end
  end

  private

  def load_user
    @user = User.find_by id: params[:followed_id]
    return if @user

    flash[:danger] = t "relationships.danger"
    redirect_to root_path
  end

  def load_relationship
    @user = Relationship.find_by(id: params[:id]).followed
    return if @user

      flash[:danger] = t "relationships.danger"
    else @user.nil?
      flash[:danger_nil] = t "relationships.danger_nil"
    end
    redirect_to root_path
  end
end
